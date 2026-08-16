mod parser;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use log::{debug, error};
use cilium_mini_common::RawDnsEvent;
use proto::DnsEvent;
use std::fs::OpenOptions;
use std::io::BufWriter;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};

pub async fn assembly_processing_topology(map: Map) -> Result<(), anyhow::Error> {
    let ring_buf = RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let async_fd = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;

    let (raw_dns_tx, raw_dns_rx) = mpsc::channel::<RawDnsEvent>(100_000);
    let (dns_tx, dns_rx) = mpsc::channel::<DnsEvent>(100_000);

    spawn_ebpf_reader(raw_dns_tx, async_fd);
    spawn_dns_parser(dns_tx, raw_dns_rx);
    spawn_file_writer(dns_rx);

    Ok(())
}

fn spawn_ebpf_reader(raw_dns_tx: Sender<RawDnsEvent>, mut async_fd: AsyncFd<RingBuf<MapData>>) {
    tokio::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() != std::mem::size_of::<RawDnsEvent>() {
                        continue;
                    }

                    let event: RawDnsEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const RawDnsEvent) };

                    if let Err(err) = raw_dns_tx.try_send(event) {
                        match err {
                            TrySendError::Full(_) => {
                                debug!(
                                    "Channel is full. Dropping packet to preserve eBPF reader speed."
                                );
                            }
                            TrySendError::Closed(_) => {
                                error!(
                                    "Event channel closed unexpectedly. Shutting down reader task."
                                );
                                return;
                            }
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    });
}

fn spawn_dns_parser(dns_tx: Sender<DnsEvent>, mut raw_dns_rx: Receiver<RawDnsEvent>) {
    std::thread::spawn(move || {
        while let Some(event) = raw_dns_rx.blocking_recv() {
            debug!("Event!!!");
        }
    });
}

fn spawn_file_writer(mut dns_rx: Receiver<DnsEvent>) {
    std::thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("00000001.ldpb") // ldpb (Length-Delimited Protocol Buffers)
            .expect("Failed to open log file");
        let mut writer = BufWriter::with_capacity(256 * 1024, file);
        while let Some(event) = dns_rx.blocking_recv() {
            debug!("Event: {:#?}", event);
        }
    });
}
