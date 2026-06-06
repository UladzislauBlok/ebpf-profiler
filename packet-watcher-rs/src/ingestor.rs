use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Context;
use aya::maps::{Map, MapData, RingBuf};
use log::info;
use packet_watcher_rs_common::{AF_INET, AF_INET6, IpAddress, PacketStats, WatchedFunction};
use prost::Message;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, Receiver, Sender};

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto.rs"));
}

use proto::ConnectionInfo;
use proto::NetworkEvent;

pub async fn start(map: Map) -> Result<(), anyhow::Error> {
    let ring_buf = RingBuf::try_from(map).context("failed to convert map to RingBuf")?;
    let (tx, rx) = mpsc::channel::<Vec<u8>>(50_000);
    let async_fd = AsyncFd::new(ring_buf).context("failed to create AsyncFd")?;
    create_buffer_reader(tx, async_fd);
    create_file_writer(rx);
    Ok(())
}

fn create_buffer_reader(
    user_space_buffer: Sender<Vec<u8>>,
    mut async_fd: AsyncFd<RingBuf<MapData>>,
) {
    tokio::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    if user_space_buffer.try_send(item.to_vec()).is_err() {
                        // Drop if channel is full to preserve engine stability
                    }
                }
                guard.clear_ready();
            }
        }
    });
}

fn create_file_writer(mut user_space_buffer: Receiver<Vec<u8>>) {
    std::thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("00000001.ldpb") // ldpb (Length-Delimited Protocol Buffers)
            .expect("Failed to open log file");
        let mut writer = BufWriter::with_capacity(256 * 1024, file);

        let mut proto_buffer = Vec::new();

        while let Some(raw_bytes) = user_space_buffer.blocking_recv() {
            if raw_bytes.len() != std::mem::size_of::<PacketStats>() {
                continue;
            }

            let c_event = unsafe { &*(raw_bytes.as_ptr() as *const PacketStats) };

            let proto_event = NetworkEvent {
                connection_info: Some(ConnectionInfo {
                    family: format_family(c_event.connection_info.family),
                    src_ip: format_ip(&c_event.connection_info.src_ip),
                    dst_ip: format_ip(&c_event.connection_info.dst_ip),
                    src_port: c_event.connection_info.src_port as u32,
                    dst_port: c_event.connection_info.dst_port as u32,
                }),
                bytes: c_event.bytes,
                function: format_function(c_event.function),
            };

            info!("Event: {:#?}", proto_event);

            proto_buffer.clear();
            proto_event.encode(&mut proto_buffer).unwrap();

            let proto_len = proto_buffer.len() as u32;

            let _ = writer.write_all(&proto_len.to_be_bytes());
            let _ = writer.write_all(&proto_buffer);
        }

        let _ = writer.flush();
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
