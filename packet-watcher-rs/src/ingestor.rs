use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use log::{debug, error};
use packet_watcher_rs_common::{AF_INET, AF_INET6, IpAddress, PacketStats, WatchedFunction};
use prost::Message;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, Receiver, Sender, error::TrySendError};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

use proto::ConnectionInfo;
use proto::NetworkEvent;

pub async fn start(map: Map) -> Result<(), anyhow::Error> {
    let ring_buf = RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let (event_tx, event_rx) = mpsc::channel::<PacketStats>(100_000); // 10_000 RPS * 10sec
    let async_fd = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;
    spawn_ebpf_reader(event_tx, async_fd);
    spawn_file_writer(event_rx);
    Ok(())
}

fn spawn_ebpf_reader(event_tx: Sender<PacketStats>, mut async_fd: AsyncFd<RingBuf<MapData>>) {
    tokio::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if item.len() != std::mem::size_of::<PacketStats>() {
                        continue;
                    }

                    let packet_stats: PacketStats =
                        unsafe { std::ptr::read_unaligned(item.as_ptr() as *const PacketStats) };

                    if let Err(err) = event_tx.try_send(packet_stats) {
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

fn spawn_file_writer(mut event_rx: Receiver<PacketStats>) {
    std::thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("00000001.ldpb") // ldpb (Length-Delimited Protocol Buffers)
            .expect("Failed to open log file");
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        let mut proto_buffer = Vec::new();

        while let Some(packet_stats) = event_rx.blocking_recv() {
            let proto_event = NetworkEvent {
                connection_info: Some(ConnectionInfo {
                    family: format_family(packet_stats.connection_info.family),
                    src_ip: format_ip(&packet_stats.connection_info.src_ip),
                    dst_ip: format_ip(&packet_stats.connection_info.dst_ip),
                    src_port: packet_stats.connection_info.src_port as u32,
                    dst_port: packet_stats.connection_info.dst_port as u32,
                }),
                bytes: packet_stats.bytes,
                function: format_function(packet_stats.function),
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

fn format_ip(ip: &IpAddress) -> String {
    match ip {
        IpAddress::V4(octets) => Ipv4Addr::from(*octets).to_string(),
        IpAddress::V6(octets) => Ipv6Addr::from(*octets).to_string(),
        IpAddress::Unknown => "unknown".to_string(),
    }
}

fn format_family(family: u16) -> String {
    match family {
        AF_INET => "IPv4".to_string(),
        AF_INET6 => "IPv6".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn format_function(func_val: u16) -> String {
    match WatchedFunction::all()
        .iter()
        .find(|f| **f as u16 == func_val)
    {
        Some(f) => f.kernel_func_name().to_string(),
        None => "unknown".to_string(),
    }
}
