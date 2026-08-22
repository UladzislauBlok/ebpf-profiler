#![no_std]

pub const RING_BUF_NAME: &str = "DNS_EVENTS_PIPE";
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const MAX_DNS_PAYLOAD_SIZE: usize = 512;

///
/// _pad to be 24 bytes (64-bit system pointer)
#[derive(Clone, Copy, Default)]
#[repr(C, align(8))]
pub struct RawIpAddr {
    pub bytes: [u8; 16],
    pub family: u32,
    _pad: u32,
}

impl RawIpAddr {
    pub const fn from_ipv4(addr: [u8; 4]) -> Self {
        Self {
            bytes: [
                addr[0], addr[1], addr[2], addr[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            family: AF_INET,
            _pad: 0,
        }
    }

    pub const fn from_ipv6(addr: [u8; 16]) -> Self {
        Self {
            bytes: addr,
            family: AF_INET6,
            _pad: 0,
        }
    }

    /// Writes the 24-byte struct as 3x 64-bit (u64) words.
    /// Guarantees zero memset/memcpy in eBPF bytecode.
    #[inline(always)]
    pub unsafe fn write_to(&self, dst: *mut RawIpAddr) {
        unsafe {
            let d = dst as *mut u64;
            let s = (self as *const Self) as *const u64;
            *d.add(0) = *s.add(0);
            *d.add(1) = *s.add(1);
            *d.add(2) = *s.add(2);
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
///   - payload_len (u16) = 2 bytes
///   - padding = 2 bytes (sum of 3 fields before is 6 bytes)
///   - payload ([u8; 512]) = 512 bytes
///   - timestamp_ns (u64) = 8 bytes
/// Total size = 576 bytes
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct RawDnsEvent {
    pub src_ip: RawIpAddr,
    pub dst_ip: RawIpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    _pad: u16,
    pub payload_len: u16,
    pub timestamp_ns: u64,
    pub payload: [u8; MAX_DNS_PAYLOAD_SIZE],
}

impl Default for RawDnsEvent {
    fn default() -> Self {
        Self {
            src_ip: RawIpAddr::default(),
            dst_ip: RawIpAddr::default(),
            src_port: 0,
            dst_port: 0,
            _pad: 0,
            payload_len: 0,
            timestamp_ns: 0,
            payload: [0; MAX_DNS_PAYLOAD_SIZE],
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RawDnsEvent {}
