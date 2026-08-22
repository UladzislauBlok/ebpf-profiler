mod parser;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use cilium_mini_common::RawDnsEvent;
use log::{debug, error};
use prost::Message;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use thingbuf::mpsc;
use tokio::io::unix::AsyncFd;

use crate::topology::parser::parse_dns_into;
use crate::topology::proto::DnsResponse;

pub fn assembly_processing_topology(map: Map) -> Result<(), anyhow::Error> {
    let ring_buf = RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let async_fd = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;

    let (raw_dns_tx, raw_dns_rx) = mpsc::channel::<RawDnsEvent>(1_000);
    let (dns_tx, dns_rx) = mpsc::blocking::channel::<DnsResponse>(1_000);

    spawn_ebpf_reader(raw_dns_tx, async_fd);
    spawn_dns_parser(dns_tx, raw_dns_rx);
    spawn_file_writer(dns_rx);

    Ok(())
}

fn spawn_ebpf_reader(
    raw_dns_tx: mpsc::Sender<RawDnsEvent>,
    mut async_fd: AsyncFd<RingBuf<MapData>>,
) {
    tokio::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() != std::mem::size_of::<RawDnsEvent>() {
                        continue;
                    }

                    match raw_dns_tx.try_send_ref() {
                        Ok(mut slot) => {
                            *slot = unsafe {
                                std::ptr::read_unaligned(item.as_ptr() as *const RawDnsEvent)
                            }
                        }
                        Err(mpsc::errors::TrySendError::Closed(_)) => {
                            error!("Event channel closed unexpectedly. Shutting down reader task.");
                            return;
                        }
                        Err(_) => {
                            debug!(
                                "Channel is full. Dropping packet to preserve eBPF reader speed."
                            );
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    });
}

fn spawn_dns_parser(
    dns_tx: mpsc::blocking::Sender<DnsResponse>,
    raw_dns_rx: mpsc::Receiver<RawDnsEvent>,
) {
    tokio::spawn(async move {
        let mut local_dns_response = DnsResponse::default();

        while let Some(raw_dns_event) = raw_dns_rx.recv_ref().await {
            parser::reset_dns_response(&mut local_dns_response);

            match parse_dns_into(&raw_dns_event, &mut local_dns_response) {
                Ok(()) => match dns_tx.try_send_ref() {
                    Ok(mut slot) => {
                        std::mem::swap(&mut *slot, &mut local_dns_response);
                    }
                    Err(mpsc::errors::TrySendError::Closed(_)) => {
                        error!("Event channel closed unexpectedly. Shutting down reader task.");
                        return;
                    }
                    Err(_) => {
                        debug!("Channel is full. Dropping packet to preserve eBPF reader speed.");
                    }
                },
                Err(e) => {
                    error!("Failed to parse DNS packet: {e}");
                }
            }
        }
    });
}

fn spawn_file_writer(dns_rx: mpsc::blocking::Receiver<DnsResponse>) {
    std::thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("00000001.ldpb") // ldpb (Length-Delimited Protocol Buffers)
            .expect("Failed to open log file");
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        let mut proto_buffer = Vec::new();

        while let Some(dns_event) = dns_rx.recv_ref() {
            debug!("Event: {dns_event:#?}");

            proto_buffer.clear();

            if let Err(e) = dns_event.encode(&mut proto_buffer) {
                error!("Error while encoding protobuf: {e}");
                continue;
            }

            let proto_len = proto_buffer.len() as u32;
            if let Err(e) = writer
                .write_all(&proto_len.to_be_bytes())
                .and_then(|_| writer.write_all(&proto_buffer))
            {
                error!("Failed to write event to commit log: {e}");
            }
        }

        let _ = writer.flush();
    });
}
