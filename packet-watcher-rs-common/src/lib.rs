#![no_std]

pub const RING_BUF_NAME: &str = "DNS_EVENTS_PIPE";
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const MAX_DNS_PAYLOAD_SIZE: usize = 512;

///
/// _pad to be 24 bytes (64-bit system pointer)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RawIpAddr {
    pub bytes: [u8; 16],
    pub family: u8,
    _pad: [u8; 7],
}

impl RawIpAddr {
    pub fn new(bytes: [u8; 16], family: u8) -> Self {
        RawIpAddr {
            bytes,
            family,
            _pad: [0; 7],
        }
    }
}

/// Shared DnsEvent payload sent from eBPF TC program to user-space
///
/// Estimated size:
///   - src_ip (RawIpAddr) = 24 bytes
///   - dst_ip (RawIpAddr) = 24 bytes
///   - src_port (u16) = 2 bytes
///   - dst_port (u16) = 2 bytes
///   - payload ([u8; 512]) = 512 bytes
///   - payload_len (u16) = 2 bytes
///   - padding = 2 bytes (sum of fields is 566 bytes)
/// Total size = 568 bytes
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RawDnsEvent {
    pub src_ip: RawIpAddr,
    pub dst_ip: RawIpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: [u8; MAX_DNS_PAYLOAD_SIZE],
    pub payload_len: u16,
    _pad: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RawDnsEvent {}
