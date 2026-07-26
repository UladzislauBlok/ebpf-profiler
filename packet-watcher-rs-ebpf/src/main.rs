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
use packet_watcher_rs_common::{DnsEvent, DnsHdr, IpAddress};

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
    let mut event = DnsEvent {
        src_ip: IpAddress::Unknown,
        dst_ip: IpAddress::Unknown,
        src_port: 0,
        dst_port: 0,
        domain_name: [0; 256],
        domain_len: 0,
        resolved_ip: IpAddress::Unknown,
        is_response: 0,
    };

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            event.src_ip = IpAddress::V4(unsafe { (*ipv4hdr).src_addr });
            event.dst_ip = IpAddress::V4(unsafe { (*ipv4hdr).dst_addr });

            match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(&ctx, EthHdr::LEN + Ipv4Hdr::LEN, &mut event)?,
                _ => return Ok(TC_ACT_OK),
            };
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            event.src_ip = IpAddress::V6(unsafe { (*ipv6hdr).src_addr });
            event.dst_ip = IpAddress::V6(unsafe { (*ipv6hdr).dst_addr });

            match unsafe { (*ipv6hdr).next_hdr().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(&ctx, EthHdr::LEN + Ipv6Hdr::LEN, &mut event)?,
                _ => return Ok(TC_ACT_OK),
            };
        }
        _ => {}
    }
    Ok(TC_ACT_OK)
}

#[inline(always)]
fn parse_udp(ctx: &TcContext, offset: usize, event: &mut DnsEvent) -> Result<i32, ()> {
    let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, offset) }?;

    event.src_port = unsafe { (*udphdr).src_port() };
    event.dst_port = unsafe { (*udphdr).dst_port() };

    // FILTER: We only care about DNS responses.
    if event.src_port != DNS_PORT {
        return Ok(TC_ACT_OK);
    }

    let dns_offset = offset + UdpHdr::LEN;
    parse_dns(ctx, dns_offset, event)
}

#[inline(always)]
fn parse_dns(ctx: &TcContext, offset: usize, event: &mut DnsEvent) -> Result<i32, ()> {
    let dns_hdr: *const DnsHdr = unsafe { ptr_at(ctx, offset) }?;

    let flags = u16::from_be(unsafe { (*dns_hdr).flags });

    // Safety check: Ensure the QR (Query/Response) bit is actually set to 1.
    // In the 16-bit flags field, QR is the highest bit (0x8000).
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return Ok(TC_ACT_OK);
    }
    event.is_response = 1;

    // TODO: Parse the variable-length domain name (event.domain_name)
    // TODO: Parse the resolved IP answer (event.resolved_ip)

    if let Some(mut buf) = DNS_EVENTS_PIPE.reserve(0) {
        unsafe {
            core::ptr::write(buf.as_mut_ptr(), *event);
        }
        buf.submit(0);
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
