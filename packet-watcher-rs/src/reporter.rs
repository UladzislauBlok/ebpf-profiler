use aya::maps::Map;
use aya::maps::PerCpuHashMap;
use log::{error, info};
use packet_watcher_rs_common::PacketStats;
use std::time::Duration;
use tokio::time::interval;

pub async fn run(map: &Map) -> anyhow::Result<()> {
    let mut interval = interval(Duration::from_secs(5));
    let stats_map: PerCpuHashMap<_, u32, PacketStats> = PerCpuHashMap::try_from(map)?;

    loop {
        interval.tick().await;

        let key: u32 = 0;
        match stats_map.get(&key, 0) {
            Ok(cpu_stats) => {
                let total_bytes: u64 = cpu_stats.iter().map(|s| s.bytes).sum();
                info!("Total bytes: {}", total_bytes);
            }
            Err(e) => {
                error!("Failed to read stats: {}", e);
            }
        }
    }
}
