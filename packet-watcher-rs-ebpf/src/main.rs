#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    btf_maps::RingBuf,
    macros::{btf_map, classifier},
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use packet_watcher_rs_common::DnsEvent;

static DNS_PORT: u16 = 53;

// We keep vmlinux for standard kernel structs if we need them later
#[allow(warnings)]
mod vmlinux;

/// The eBPF ring buffer for DNS events.
///
/// Sizing calculations:
/// - Page size: 4096 bytes (ringbuf size must be a power-of-2 multiple of page size).
/// - DnsEvent size: 328 bytes + 8 bytes kernel header = 336 bytes per entry.
/// - Capacity estimate: 10,000 events/sec * 336 bytes * 10 sec = 33,600,000 bytes.
/// - Chosen size: 67,108,864 bytes (64 MB, power of 2, page-aligned).
#[btf_map(name = "DNS_EVENTS_PIPE")]
static DNS_EVENTS_PIPE: RingBuf<DnsEvent, 67108864, 0> = RingBuf::new();

#[classifier]
pub fn dns_tc(ctx: TcContext) -> i32 {
    match try_dns_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

fn try_dns_tc(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Tcp => return Ok(TC_ACT_OK),
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    let port = unsafe { (*udphdr).src_port() };
                    if port != DNS_PORT {
                        return Ok(TC_ACT_OK);
                    }
                    info!(&ctx, "DNS V4");
                }
                _ => return Ok(TC_ACT_OK),
            };
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            match unsafe { (*ipv6hdr).next_hdr().map_err(|_: IpError| ())? } {
                IpProto::Tcp => return Ok(TC_ACT_OK),
                IpProto::Udp => {
                    let udphdr: *const UdpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN) }?;
                    let port = unsafe { (*udphdr).src_port() };
                    if port != DNS_PORT {
                        return Ok(TC_ACT_OK);
                    }
                    info!(&ctx, "DNS V6");
                }
                _ => return Ok(TC_ACT_OK),
            };
        }
        _ => {}
    }
    Ok(TC_ACT_OK)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
