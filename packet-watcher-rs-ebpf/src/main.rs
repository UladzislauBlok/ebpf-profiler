#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    btf_maps::RingBuf,
    macros::{btf_map, classifier},
    programs::TcContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use packet_watcher_rs_common::{AF_INET, AF_INET6, MAX_DNS_PAYLOAD_SIZE, RawDnsEvent, RawIpAddr};

static DNS_PORT: u16 = 53;

/// The number of bytes per 32-bit word unit in the IPv4 IHL (Internet Header Length) field.
/// Reference: RFC 791 Section 3.1
const BYTES_PER_IHL_WORD: usize = 4;

// We keep vmlinux for standard kernel structs if we need them later
#[allow(warnings)]
mod vmlinux;

/// The eBPF ring buffer for DNS events.
///
/// Sizing calculations:
/// - Page size: 4096 bytes (ringbuf size must be a power-of-2 multiple of page size).
/// - RawDnsEvent size: 568 bytes + 8 bytes kernel header = 576 bytes per entry.
/// - Capacity estimate: 10,000 events/sec * 576 bytes * 10 sec = 57,600,000 bytes.
/// - Chosen size: 67,108,864 bytes (64 MB, power of 2, page-aligned).
#[btf_map(name = "DNS_EVENTS_PIPE")]
static DNS_EVENTS_PIPE: RingBuf<RawDnsEvent, 67108864, 0> = RingBuf::new();

#[classifier]
pub fn dns_tc(ctx: TcContext) -> i32 {
    match try_dns_tc(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

fn try_dns_tc(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let mut src_ip: [u8; 16] = [0; 16];
    let mut dst_ip: [u8; 16] = [0; 16];
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            src_ip[..4].copy_from_slice(&unsafe { (*ipv4hdr).src_addr });
            dst_ip[..4].copy_from_slice(&unsafe { (*ipv4hdr).dst_addr });

            let ip_hdr_len = get_ipv4_header_len(ipv4hdr);

            match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(
                    &ctx,
                    EthHdr::LEN + ip_hdr_len,
                    RawIpAddr::new(src_ip, AF_INET),
                    RawIpAddr::new(dst_ip, AF_INET),
                )?,
                _ => return Ok(TC_ACT_OK),
            };
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            src_ip.copy_from_slice(&unsafe { (*ipv6hdr).src_addr });
            dst_ip.copy_from_slice(&unsafe { (*ipv6hdr).dst_addr });

            match unsafe { (*ipv6hdr).next_hdr().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(
                    &ctx,
                    EthHdr::LEN + Ipv6Hdr::LEN,
                    RawIpAddr::new(src_ip, AF_INET6),
                    RawIpAddr::new(dst_ip, AF_INET6),
                )?,
                _ => return Ok(TC_ACT_OK),
            };
        }
        _ => {}
    }
    Ok(TC_ACT_OK)
}

#[inline(always)]
fn parse_udp(
    ctx: &TcContext,
    offset: usize,
    src_ip: RawIpAddr,
    dst_ip: RawIpAddr,
) -> Result<i32, ()> {
    let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, offset) }?;

    let src_port = unsafe { (*udphdr).src_port() };
    let dst_port = unsafe { (*udphdr).dst_port() };

    // FILTER: We only care about DNS responses.
    if src_port != DNS_PORT {
        return Ok(TC_ACT_OK);
    }

    let payload_offset = offset + UdpHdr::LEN;

    let payload_src_ptr: *const u8 = unsafe { ptr_at::<u8>(ctx, payload_offset) }?;

    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let available_len = data_end.saturating_sub(data_start + payload_offset);

    if available_len == 0 {
        return Ok(TC_ACT_OK);
    }

    let payload_len = available_len.min(MAX_DNS_PAYLOAD_SIZE);

    if let Some(mut ring_buf) = DNS_EVENTS_PIPE.reserve(0) {
        let event_ptr: *mut RawDnsEvent = ring_buf.as_mut_ptr() as *mut RawDnsEvent;

        unsafe {
            (*event_ptr).src_ip = src_ip;
            (*event_ptr).dst_ip = dst_ip;
            (*event_ptr).src_port = src_port;
            (*event_ptr).dst_port = dst_port;
            (*event_ptr).payload_len = payload_len as u16;
            core::ptr::copy_nonoverlapping(
                payload_src_ptr,
                (*event_ptr).payload.as_mut_ptr(),
                payload_len,
            );
        }

        ring_buf.submit(0);
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

#[inline(always)]
fn get_ipv4_header_len(ipv4hdr: *const Ipv4Hdr) -> usize {
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    ihl * BYTES_PER_IHL_WORD
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
