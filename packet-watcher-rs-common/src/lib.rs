#![no_std]

pub const RING_BUF_NAME: &str = "DNS_EVENTS_PIPE";
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

#[derive(Clone, Copy)]
#[repr(C)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
    Unknown,
}

/// Shared DnsEvent payload sent from eBPF TC program to user-space
///
/// Estimated size:
///   - src_ip (IpAddress) = 20 bytes
///   - dst_ip (IpAddress) = 20 bytes
///   - src_port (u16) = 2 bytes
///   - dst_port (u16) = 2 bytes
///   - domain_name ([u8; 256]) = 256 bytes
///   - domain_len (u32) = 4 bytes
///   - resolved_ip (IpAddress) = 20 bytes
///   - is_response (u8) = 1 byte
///   - padding = 3 bytes
/// Total size = 328 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DnsEvent {
    pub src_ip: IpAddress,
    pub dst_ip: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
    pub domain_name: [u8; 256],
    pub domain_len: u32,
    pub resolved_ip: IpAddress,
    pub is_response: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DnsEvent {}
