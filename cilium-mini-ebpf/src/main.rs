#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    btf_maps::RingBuf,
    macros::{btf_map, classifier},
    programs::TcContext,
};
use aya_log_ebpf::debug;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use cilium_mini_common::{MAX_DNS_PAYLOAD_SIZE, RawDnsEvent, RawIpAddr};

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
    match unsafe { *ethhdr }.ether_type() {
        Ok(EtherType::Ipv4) => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            let src_ip = RawIpAddr::from_ipv4(unsafe { (*ipv4hdr).src_addr });
            let dst_ip = RawIpAddr::from_ipv4(unsafe { (*ipv4hdr).dst_addr });

            let ip_hdr_len = get_ipv4_header_len(ipv4hdr, &ctx)?;

            match unsafe { (*ipv4hdr).proto().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(&ctx, EthHdr::LEN + ip_hdr_len, src_ip, dst_ip)?,
                _ => return Ok(TC_ACT_OK),
            };
        }
        Ok(EtherType::Ipv6) => {
            let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

            let src_ip = RawIpAddr::from_ipv6(unsafe { (*ipv6hdr).src_addr });
            let dst_ip = RawIpAddr::from_ipv6(unsafe { (*ipv6hdr).dst_addr });

            match unsafe { (*ipv6hdr).next_hdr().map_err(|_: IpError| ())? } {
                IpProto::Udp => parse_udp(&ctx, EthHdr::LEN + Ipv6Hdr::LEN, src_ip, dst_ip)?,
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

    debug!(
        &ctx,
        "UDP in. src_port: {}; dst_port: {}", src_port, dst_port
    );

    // FILTER: We only care about DNS responses.
    if src_port != DNS_PORT {
        return Ok(TC_ACT_OK);
    }

    let payload_offset = offset + UdpHdr::LEN;

    let data_start = ctx.data();
    let data_end = ctx.data_end();
    let available_len = data_end.saturating_sub(data_start + payload_offset);

    if available_len == 0 {
        return Ok(TC_ACT_OK);
    }

    debug!(&ctx, "DNS in");

    if let Some(mut ring_buf) = DNS_EVENTS_PIPE.reserve(0) {
        let event_ptr: *mut RawDnsEvent = ring_buf.as_mut_ptr() as *mut RawDnsEvent;

        unsafe {
            src_ip.write_to(core::ptr::addr_of_mut!((*event_ptr).src_ip));
            dst_ip.write_to(core::ptr::addr_of_mut!((*event_ptr).dst_ip));
            (*event_ptr).src_port = src_port;
            (*event_ptr).dst_port = dst_port;
        }

        let dst_payload = unsafe { &mut (*event_ptr).payload };
        let mut copied_len: u16 = 0;

        for i in 0..MAX_DNS_PAYLOAD_SIZE {
            let cur_offset = payload_offset + i;

            if data_start + cur_offset + 1 > data_end {
                break;
            }

            let byte_ptr: *const u8 = (data_start + cur_offset) as *const u8;
            dst_payload[i] = unsafe { *byte_ptr };
            copied_len += 1;
        }

        unsafe {
            (*event_ptr).payload_len = copied_len;
        }

        debug!(&ctx, "DNS out");

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
fn get_ipv4_header_len(ipv4hdr: *const Ipv4Hdr, ctx: &TcContext) -> Result<usize, ()> {
    let raw_ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let ihl = raw_ihl & 0x0F;
    debug!(&ctx, "IHL res: {}", ihl);
    // RFC 791: Minimum is 5 (20 bytes), maximum is 15 (60 bytes)
    if ihl < 5 || ihl > 15 {
        return Err(());
    }
    Ok(ihl * BYTES_PER_IHL_WORD)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
