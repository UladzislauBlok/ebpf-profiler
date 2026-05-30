#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_kernel,
    macros::{fexit, map},
    maps::PerCpuArray,
    programs::FExitContext,
};
use aya_log_ebpf::error;
use packet_watcher_rs_common::{
    AF_INET, AF_INET6, ConnectionInfo, IpAddress, PacketStats, WatchedFunction,
};

mod vmlinux;
use vmlinux::sock;

#[map(name = "STATS")]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(WatchedFunction::COUNT, 0);

/// Probes the exit of `tcp_sendmsg` to capture TCP transmission statistics.
///
/// Kernel function signature:
/// `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`
///
/// In the `fexit` program context:
/// - `ctx.arg(0)` is the `sk` pointer (`struct sock *`).
/// - `ctx.arg(3)` is the return value representing the bytes sent (the argument following the last parameter).
#[fexit]
fn tcp_sendmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(3);
    match try_packet_watcher_rs(sk_ptr, bytes, WatchedFunction::TcpSendmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[fexit]
fn tcp_recvmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(5);
    match try_packet_watcher_rs(sk_ptr, bytes, WatchedFunction::TcpRecvmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in tcp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[fexit]
fn udp_sendmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(3);
    match try_packet_watcher_rs(sk_ptr, bytes, WatchedFunction::UdpSendmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_sendmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

#[fexit]
fn udp_recvmsg_fexit(ctx: FExitContext) -> u32 {
    let sk_ptr: *const sock = ctx.arg(0);
    let bytes: i32 = ctx.arg(5);
    match try_packet_watcher_rs(sk_ptr, bytes, WatchedFunction::UdpRecvmsg as u32) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error in udp_recvmsg_probe: {}", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

fn try_packet_watcher_rs(
    sk_ptr: *const sock,
    bytes: i32,
    map_key: u32,
) -> Result<u32, u32> {
    if bytes <= 0 {
        return Ok(0); // Expected for non-blocking socket
    }
    let connection_info = read_connection_info(sk_ptr).map_err(|_| 1u32)?;
    insert_to_map(map_key, bytes, connection_info).map_err(|()| 1u32)?;
    Ok(0)
}

fn read_connection_info(sk_ptr: *const sock) -> Result<ConnectionInfo, i32> {
    let family = unsafe { bpf_probe_read_kernel(&(*sk_ptr).__sk_common.skc_family) }?;

    match family {
        AF_INET => read_v4(sk_ptr),
        AF_INET6 => read_v6(sk_ptr),
        _ => Err(1),
    }
}

fn read_v4(sk_ptr: *const sock) -> Result<ConnectionInfo, i32> {
    // union {
    //     __addrpair skc_addrpair;
    //     struct {
    //         __be32 skc_daddr;
    //         __be32 skc_rcv_saddr;
    //     };
    // };
    let ports = read_ports(sk_ptr)?;
    unsafe {
        let saddr = bpf_probe_read_kernel(
            &(*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr,
        )?;
        let daddr = bpf_probe_read_kernel(
            &(*sk_ptr)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr,
        )?;
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
        let saddr6 = bpf_probe_read_kernel(&(*sk_ptr).__sk_common.skc_v6_rcv_saddr)?;
        let daddr6 = bpf_probe_read_kernel(&(*sk_ptr).__sk_common.skc_v6_daddr)?;
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
    // union {
    //     __portpair skc_portpair;
    //     struct {
    //        __be16 skc_dport;
    //        __u16 skc_num;
    //     };
    // };
    unsafe {
        let src_port = bpf_probe_read_kernel(
            &(*sk_ptr)
                .__sk_common
                .__bindgen_anon_3
                .__bindgen_anon_1
                .skc_num,
        )?;

        let dst_port_raw = bpf_probe_read_kernel(
            &(*sk_ptr)
                .__sk_common
                .__bindgen_anon_3
                .__bindgen_anon_1
                .skc_dport,
        )?;
        let dst_port = u16::from_be(dst_port_raw);
        Ok((src_port, dst_port))
    }
}

fn insert_to_map(index: u32, bytes: i32, connection_info: ConnectionInfo) -> Result<(), ()> {
    let stats = STATS.get_ptr_mut(index).ok_or(())?;
    unsafe {
        (*stats).bytes = bytes;
        (*stats).connection_info = connection_info;
    };
    Ok(())
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
