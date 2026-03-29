use aya::maps::Map;
use aya::maps::PerCpuArray;
use log::{debug, error};
use packet_watcher_rs_common::PacketStats;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

pub async fn run(map: &Map) -> anyhow::Result<()> {
    let stats_map: PerCpuArray<_, PacketStats> = PerCpuArray::try_from(map)?;
    let listener = TcpListener::bind("0.0.0.0:9091").await?;
    loop {
        match listener.accept().await {
            Ok((mut socket, addr)) => match stats_map.get(&0, 0) {
                Ok(cpu_stats) => {
                    debug!("Open connection from {}", addr);
                    let total_bytes: u64 = cpu_stats.iter().map(|s| s.bytes).sum();
                    send_response(total_bytes, &mut socket).await?;
                }
                Err(e) => {
                    error!("Failed to read stats: {}", e);
                }
            },
            Err(e) => error!("couldn't get client: {}", e),
        }
    }
}

async fn send_response(bytes: u64, socket: &mut TcpStream) -> anyhow::Result<()> {
    let body = format!("packet_watcher_bytes_total {}\n", bytes);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain;\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    debug!("Try to send respose \n{}", response);
    Ok(socket.write_all(response.as_bytes()).await?)
}
