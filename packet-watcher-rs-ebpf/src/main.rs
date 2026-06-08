#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::RingBuf,
    macros::{btf_map, fexit},
    programs::FExitContext,
};
use aya_log_ebpf::error;
use packet_watcher_rs_common::{
    AF_INET, AF_INET6, ConnectionInfo, IpAddress, PacketStats, WatchedFunction,
};

#[allow(warnings)]
mod vmlinux;
use vmlinux::sock;

/// The eBPF ring buffer for transport layer events.
///
/// Sizing calculations:
/// - Page size: 4096 bytes (ringbuf size must be a power-of-2 multiple of page size).
/// - PacketStats size: 56 bytes + 8 bytes kernel header = 64 bytes per entry.
/// - Capacity estimate: 10,000 events/sec * 64 bytes * 10 sec = 6,400,000 bytes.
/// - Chosen size: 8,388,608 bytes (8 MB, power of 2, page-aligned).
#[btf_map(name = "PACKET_STATS_PIPE")]
static PACKER_STATS_PIPE: RingBuf<PacketStats, 8388608, 0> = RingBuf::new();

/// Probes the exit of `tcp_sendmsg` to capture TCP transmission statistics.
///
/// Kernel function signature:
/// `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/include/net/tcp.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(3)` is the return value representing the bytes sent (the argument following the last parameter).
#[fexit]
fn tcp_sendmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(3);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::TcpSendmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

/// Probes the exit of `tcp_recvmsg` to capture TCP transmission statistics.
///
/// Kernel function signature:
/// `int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/include/net/tcp.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(5)` is the return value representing the bytes sent (the argument following the last parameter).
#[fexit]
fn tcp_recvmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(5);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::TcpRecvmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

/// Probes the exit of `udp_sendmsg` to capture UDP IPv4 transmission statistics.
///
/// Kernel function signature:
/// `int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/include/net/udp.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(3)` is the return value representing the bytes sent (the argument following the last parameter).
#[fexit]
fn udp_sendmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(3);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::UdpSendmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

/// Probes the exit of `udp_recvmsg` to capture UDP IPv4 transmission statistics.
///
/// Kernel function signature:
/// `int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/net/ipv4/udp_impl.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(5)` is the return value representing the bytes received (the argument following the last parameter).
#[fexit]
fn udp_recvmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(5);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::UdpRecvmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

/// Probes the exit of `udpv6_sendmsg` to capture UDP IPv6 transmission statistics.
///
/// Kernel function signature:
/// `int udpv6_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/net/ipv6/udp_impl.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(3)` is the return value representing the bytes sent.
#[fexit]
fn udpv6_sendmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(3);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::Udpv6Sendmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udpv6_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

/// Probes the exit of `udpv6_recvmsg` to capture UDP IPv6 transmission statistics.
///
/// Kernel function signature:
/// `int udpv6_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len);`
///
/// Kernel version: v7.0.11
/// Docs: https://elixir.bootlin.com/linux/v7.0.11/source/net/ipv6/udp_impl.h
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(5)` is the return value representing the bytes received.
#[fexit]
fn udpv6_recvmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(5);
    match intercept_packet(sk_ptr, bytes, WatchedFunction::Udpv6Recvmsg as u16) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udpv6_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

fn intercept_packet(sk_ptr: *const sock, bytes: i32, map_key: u16) -> Result<u32, u32> {
    if bytes < 0 {
        return Ok(0); // Expected for non-blocking socket
    }
    if sk_ptr.is_null() {
        return Ok(0);
    }
    let connection_info = read_connection_info(sk_ptr).map_err(|_| 1u32)?;
    pipe_packet_stats(map_key, bytes, connection_info).map_err(|()| 1u32)?;
    Ok(0)
}

fn read_connection_info(sk_ptr: *const sock) -> Result<ConnectionInfo, i32> {
    let family = unsafe { (*sk_ptr).__sk_common.skc_family };

    match family {
        AF_INET => read_v4(sk_ptr),
        AF_INET6 => read_v6(sk_ptr),
        _ => Err(1),
    }
}

fn read_v4(sk_ptr: *const sock) -> Result<ConnectionInfo, i32> {
    let ports = read_ports(sk_ptr)?;
    unsafe {
        let saddr = (*sk_ptr)
            .__sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_rcv_saddr;
        let daddr = (*sk_ptr)
            .__sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_daddr;
        Ok(ConnectionInfo {
            family: AF_INET,
            src_ip: IpAddress::V4(saddr.to_ne_bytes()),
            dst_ip: IpAddress::V4(daddr.to_ne_bytes()),
            dst_port: ports.1,
            src_port: ports.0,
        })
    }
}

fn read_v6(sk_ptr: *const sock) -> Result<ConnectionInfo, i32> {
    let ports = read_ports(sk_ptr)?;
    unsafe {
        let saddr6 = (*sk_ptr).__sk_common.skc_v6_rcv_saddr;
        let daddr6 = (*sk_ptr).__sk_common.skc_v6_daddr;
        let src_bytes = saddr6.in6_u.u6_addr8;
        let dst_bytes = daddr6.in6_u.u6_addr8;
        Ok(ConnectionInfo {
            family: AF_INET6,
            src_ip: IpAddress::V6(src_bytes),
            dst_ip: IpAddress::V6(dst_bytes),
            dst_port: ports.1,
            src_port: ports.0,
        })
    }
}

fn read_ports(sk_ptr: *const sock) -> Result<(u16, u16), i32> {
    unsafe {
        let src_port = (*sk_ptr)
            .__sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_num;
        let dst_port_raw = (*sk_ptr)
            .__sk_common
            .__bindgen_anon_3
            .__bindgen_anon_1
            .skc_dport;
        let dst_port = u16::from_be(dst_port_raw);
        Ok((src_port, dst_port))
    }
}

fn pipe_packet_stats(function: u16, bytes: i32, connection_info: ConnectionInfo) -> Result<(), ()> {
    if let Some(mut entry) = PACKER_STATS_PIPE.reserve(0) {
        entry.write(PacketStats {
            connection_info,
            bytes,
            function,
        });
        entry.submit(0);
        Ok(())
    } else {
        Err(())
    }
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
