#![no_std]

/// Should match name of BTF map
pub const RING_BUF_NAME: &str = "PACKET_STATS_PIPE";
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Estimated size:
/// ConnectionInfo  subtotal = 46 bytes (padded to 48 bytes for 4-byte alignment)
///   - family  ( u16 ) = 2 bytes
///   - src_ip  ( IpAddress ) = Tag  u32  (4 bytes, due to #[repr(C)]) + Payload  [u8; 16]  (16 bytes) = 20 bytes
///   - dst_ip  ( IpAddress ) = 20 bytes
///   - src_port  /  dst_port  ( u16  +  u16 ) = 4 bytes
/// bytes  ( i32 ) = 4 bytes
/// function  ( u16 ) = 2 bytes
///
/// Total  PacketStats  size = 56 bytes (padded to 56 bytes for 4-byte alignment)
///
/// Note on IpAddress size: Due to #[repr(C)] on `IpAddress`, the enum discriminant tag uses 4 bytes (u32).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketStats {
    pub connection_info: ConnectionInfo,
    pub bytes: i32,
    pub function: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectionInfo {
    pub family: u16,
    pub src_ip: IpAddress,
    pub dst_ip: IpAddress,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
    Unknown,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketStats {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum WatchedFunction {
    TcpSendmsg = 0,
    TcpRecvmsg = 1,
    UdpSendmsg = 2,
    UdpRecvmsg = 3,
}

impl WatchedFunction {
    pub const COUNT: u16 = 4;

    pub const fn kernel_func_name(&self) -> &'static str {
        match self {
            WatchedFunction::TcpSendmsg => "tcp_sendmsg",
            WatchedFunction::TcpRecvmsg => "tcp_recvmsg",
            WatchedFunction::UdpSendmsg => "udp_sendmsg",
            WatchedFunction::UdpRecvmsg => "udp_recvmsg",
        }
    }

    /// These names must match the function names defined in the eBPF program
    pub const fn fexit_func_name(&self) -> &'static str {
        match self {
            WatchedFunction::TcpSendmsg => "tcp_sendmsg_fexit",
            WatchedFunction::TcpRecvmsg => "tcp_recvmsg_fexit",
            WatchedFunction::UdpSendmsg => "udp_sendmsg_fexit",
            WatchedFunction::UdpRecvmsg => "udp_recvmsg_fexit",
        }
    }

    pub const fn all() -> &'static [WatchedFunction] {
        &[
            WatchedFunction::TcpSendmsg,
            WatchedFunction::TcpRecvmsg,
            WatchedFunction::UdpSendmsg,
            WatchedFunction::UdpRecvmsg,
        ]
    }
}
