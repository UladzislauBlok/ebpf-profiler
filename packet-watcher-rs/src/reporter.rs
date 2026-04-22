use aya::maps::Map;
use aya::maps::PerCpuArray;
use log::{debug, error};
use packet_watcher_rs_common::{PacketStats, WatchedFunction};
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
                            let total_bytes: u64 = cpu_stats.iter().map(|s| s.bytes).sum();
                            body.push_str(&format!(
                                "packet_watcher_bytes_total{{function=\"{}\"}} {}\n",
                                func.kernel_func_name(),
                                total_bytes
                            ));
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
