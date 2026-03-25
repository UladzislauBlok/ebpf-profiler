#![no_std]

pub const PROBE_NAME: &str = "paccher_rs";
pub const DEFAULT_FUNCTION: &str = "tcp_recvmsg";
pub const DEFAULT_MAP_NAME: &str = "BYTES_PER_CPU";

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketStats {
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}
