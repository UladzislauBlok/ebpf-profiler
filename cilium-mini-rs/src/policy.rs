use std::collections::HashSet;

use anyhow::{Context, anyhow};
use aya::maps::{HashMap, Map, MapData};
use cilium_mini_common::{AF_INET, AF_INET6, RawIpAddr};
use log::info;

use super::proto::DnsResponse;

pub trait DnsObserver: Send + 'static {
    fn update(&mut self, dns_response: &DnsResponse) -> anyhow::Result<()>;
}

pub struct FqdnPolicyEngine {
    allowed_ip_map: HashMap<MapData, RawIpAddr, u8>,
    allowed_domains: HashSet<String>,
}

impl DnsObserver for FqdnPolicyEngine {
    fn update(&mut self, dns_response: &DnsResponse) -> anyhow::Result<()> {
        if !self.allowed_domains.contains(&dns_response.domain_name) {
            info!("Skipping unknown domain: {}", &dns_response.domain_name);
            return Ok(());
        }
        let ip_addr = match dns_response.ip_family {
            AF_INET => RawIpAddr::from_ipv4(
                dns_response
                    .resolved_ip_raw
                    .chunks_exact(4)
                    .next()
                    .unwrap()
                    .try_into()
                    .map_err(|_| {
                        anyhow!(
                            "expected 4 bytes for IPv4, got {}",
                            dns_response.resolved_ip_raw.len()
                        )
                    })?,
            ),
            AF_INET6 => RawIpAddr::from_ipv6(
                dns_response
                    .resolved_ip_raw
                    .chunks_exact(16)
                    .next()
                    .unwrap()
                    .try_into()
                    .map_err(|_| {
                        anyhow!(
                            "expected 16 bytes for IPv6, got {}",
                            dns_response.resolved_ip_raw.len()
                        )
                    })?,
            ),
            _ => {
                return Err(anyhow!(
                    "Ip family should be already parsed, so this is a bug"
                ));
            }
        };
        self.allowed_ip_map.insert(ip_addr, 0, 0)?;
        info!(
            "Updated hash map with domain: {}",
            &dns_response.domain_name
        );
        Ok(())
    }
}

impl FqdnPolicyEngine {
    pub fn new(ebpf_map: Map, allowed_domains: HashSet<String>) -> Result<Self, anyhow::Error> {
        Ok(Self {
            allowed_ip_map: HashMap::try_from(ebpf_map)
                .context("failed to convert map to HashMap")?,
            allowed_domains: allowed_domains,
        })
    }
}
