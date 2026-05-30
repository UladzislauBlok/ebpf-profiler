use aya::maps::Map;
use aya::maps::PerCpuArray;
use log::{debug, error};
use packet_watcher_rs_common::{AF_INET, AF_INET6, IpAddress, PacketStats, WatchedFunction};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

pub async fn run(map: &Map) -> anyhow::Result<()> {
    let stats_map: PerCpuArray<_, PacketStats> = PerCpuArray::try_from(map)?;
    let listener = TcpListener::bind("0.0.0.0:9091").await?;
    loop {
        match listener.accept().await {
            Ok((mut socket, addr)) => {
                debug!("Open connection from {}", addr);
                let mut body = String::new();

                for func in WatchedFunction::all() {
                    let index = *func as u32;
                    match stats_map.get(&index, 0) {
                        Ok(cpu_stats) => {
                            for (cpu_id, stats) in cpu_stats.iter().enumerate() {
                                let conn = &stats.connection_info;
                                if conn.family == AF_INET || conn.family == AF_INET6 {
                                    let family_str = if conn.family == AF_INET {
                                        "IPv4"
                                    } else {
                                        "IPv6"
                                    };
                                    body.push_str(&format!(
                                        "packet_watcher_last_connection{{function=\"{}\",cpu=\"{}\",family=\"{}\",src=\"{}:{}\",dst=\"{}:{}\"}} {}\n",
                                        func.kernel_func_name(),
                                        cpu_id,
                                        family_str,
                                        format_ip(&conn.src_ip),
                                        conn.src_port,
                                        format_ip(&conn.dst_ip),
                                        conn.dst_port,
                                        stats.bytes
                                    ));
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                "Failed to read stats for {}: {}",
                                func.kernel_func_name(),
                                e
                            );
                        }
                    }
                }

                if let Err(e) = send_response(&body, &mut socket).await {
                    error!("Failed to send response: {}", e);
                }
            }
            Err(e) => error!("couldn't get client: {}", e),
        }
    }
}

async fn send_response(body: &str, socket: &mut TcpStream) -> anyhow::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    debug!("Try to send response \n{}", response);
    Ok(socket.write_all(response.as_bytes()).await?)
}

fn format_ip(ip: &IpAddress) -> String {
    match ip {
        IpAddress::V4(octets) => format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]),
        IpAddress::V6(octets) => {
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                octets[4],
                octets[5],
                octets[6],
                octets[7],
                octets[8],
                octets[9],
                octets[10],
                octets[11],
                octets[12],
                octets[13],
                octets[14],
                octets[15]
            )
        }
        IpAddress::Unknown => "unknown".to_string(),
    }
}
