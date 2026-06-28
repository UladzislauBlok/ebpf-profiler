use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use log::{debug, error};
use packet_watcher_rs_common::{DnsEvent, IpAddress};
use prost::Message;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

use proto::DnsEvent as ProtoDnsEvent;

pub async fn start(map: Map) -> Result<(), anyhow::Error> {
    let ring_buf = RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let (event_tx, event_rx) = mpsc::channel::<DnsEvent>(100_000); // 100k capacity
    let async_fd = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;
    spawn_ebpf_reader(event_tx, async_fd);
    spawn_file_writer(event_rx);
    Ok(())
}

fn spawn_ebpf_reader(event_tx: Sender<DnsEvent>, mut async_fd: AsyncFd<RingBuf<MapData>>) {
    tokio::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() != std::mem::size_of::<DnsEvent>() {
                        continue;
                    }

                    let event: DnsEvent =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const DnsEvent) };

                    if let Err(err) = event_tx.try_send(event) {
                        match err {
                            TrySendError::Full(_) => {
                                debug!("Channel is full. Dropping packet to preserve eBPF reader speed.");
                            }
                            TrySendError::Closed(_) => {
                                error!("Event channel closed unexpectedly. Shutting down reader task.");
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

fn format_ip(ip: &IpAddress) -> String {
    match ip {
        IpAddress::V4(octets) => Ipv4Addr::from(*octets).to_string(),
        IpAddress::V6(octets) => Ipv6Addr::from(*octets).to_string(),
        IpAddress::Unknown => "unknown".to_string(),
    }
}

fn spawn_file_writer(mut event_rx: Receiver<DnsEvent>) {
    std::thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("00000001.ldpb") // ldpb (Length-Delimited Protocol Buffers)
            .expect("Failed to open log file");
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        let mut proto_buffer = Vec::new();

        while let Some(event) = event_rx.blocking_recv() {
            // Convert C string/buffer to Rust string
            let domain_len = std::cmp::min(event.domain_len as usize, 256);
            let domain_name = String::from_utf8_lossy(&event.domain_name[..domain_len]).into_owned();

            let resolved_ip = if event.is_response == 1 {
                Some(format_ip(&event.resolved_ip))
            } else {
                None
            };

            let proto_event = ProtoDnsEvent {
                src_ip: format_ip(&event.src_ip),
                dst_ip: format_ip(&event.dst_ip),
                src_port: event.src_port as u32,
                dst_port: event.dst_port as u32,
                domain_name,
                resolved_ip,
                is_response: event.is_response == 1,
            };

            debug!("Event: {:#?}", proto_event);

            proto_buffer.clear();
            proto_event.encode(&mut proto_buffer).unwrap();

            let proto_len = proto_buffer.len() as u32;

            if let Err(e) = writer.write_all(&proto_len.to_be_bytes()) {
                error!("Failed to write length to disk: {}", e);
            }
            if let Err(e) = writer.write_all(&proto_buffer) {
                error!("Failed to write protobuf data to disk: {}", e);
            }
        }

        if let Err(e) = writer.flush() {
            error!("Failed to flush writer to disk: {}", e);
        }
    });
}
