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

/// Evaluates and parses DNS Response packets passing through Traffic Control (TC).
///
/// Full DNS Packet Structure (RFC 1035 Section 4.1):
/// +---------------------------------------------------+
/// | Header     (12 bytes) - ID, Flags, Record Counts  |
/// +---------------------------------------------------+
/// | Question   (Variable) - QNAME + QTYPE(2B) + QCLASS|
/// +---------------------------------------------------+
/// | Answer     (Variable) - NAME + Record Header + IP |
/// +---------------------------------------------------+
/// | Authority  (Skipped)  - Authoritative NS records  |
/// +---------------------------------------------------+
/// | Additional (Skipped)  - EDNS0 & Metadata options  |
/// +---------------------------------------------------+
#[inline(always)]
fn parse_dns(ctx: &TcContext, mut offset: usize, event: &mut DnsEvent) -> Result<i32, ()> {
    let dns_hdr: *const DnsHdr = unsafe { ptr_at(ctx, offset) }?;

    let flags = u16::from_be(unsafe { (*dns_hdr).flags });

    // Safety check: Ensure the QR (Query/Response) bit is actually set to 1.
    // In the 16-bit flags field, QR is the highest bit (0x8000).
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return Ok(TC_ACT_OK);
    }
    event.is_response = 1;

    // QNAME  - n bytes
    // QTYPE  - 2 bytes
    // QCLASS - 2 bytes
    offset = parse_qname(ctx, offset + DnsHdr::LEN, event)? + 4;

    parse_rdata(ctx, offset, event)?;

    if let Some(mut buf) = DNS_EVENTS_PIPE.reserve(0) {
        unsafe {
            core::ptr::write(buf.as_mut_ptr(), *event);
        }
        buf.submit(0);
    }

    Ok(TC_ACT_OK)
}

/// Parses variable-length length-prefixed DNS domain labels (`QNAME`) from the Question section.
///
/// Question Section Wire Layout (RFC 1035 Section 4.1.2):
/// +---------------------------------------------------+
/// | QNAME  (Variable: length-prefixed domain labels) |
/// |        e.g. \x03www\x06google\x03com\x00           |
/// +---------------------------------------------------+
/// | QTYPE  (2 bytes) - 0x0001 (A), 0x001C (AAAA), etc.|
/// +---------------------------------------------------+
/// | QCLASS (2 bytes) - 0x0001 (IN - Internet)         |
/// +---------------------------------------------------+
///
/// Label Encoding:
/// - Each domain label starts with a 1-byte length prefix (0x01 to 0x3F).
/// - QNAME terminates with a null byte (0x00).
/// - Dot separators ('.') are inserted between labels into `event.domain_name`.
#[inline(always)]
fn parse_qname(ctx: &TcContext, mut offset: usize, event: &mut DnsEvent) -> Result<usize, ()> {
    let mut out_idx: usize = 0;
    let mut label_remaining: usize = 0;

    for _ in 0..256 {
        if label_remaining == 0 {
            // Read 1-byte label length
            let len_ptr: *const u8 = unsafe { ptr_at(ctx, offset)? };
            let label_len = unsafe { *len_ptr } as usize;
            offset += 1;

            // 0x00 indicates end of QNAME
            if label_len == 0 {
                event.domain_len = out_idx as u32;
                return Ok(offset);
            }

            // https://datatracker.ietf.org/doc/html/rfc1035
            // RFC 1035: Label length cannot exceed 63 bytes
            if label_len > 63 {
                return Err(());
            }

            // Add dot separator between labels (e.g. "www" -> "www.")
            if out_idx > 0 && out_idx < 256 {
                event.domain_name[out_idx] = b'.';
                out_idx += 1;
            }

            label_remaining = label_len;
        } else {
            if out_idx >= 256 {
                return Err(());
            }

            let char_ptr: *const u8 = unsafe { ptr_at(ctx, offset)? };
            event.domain_name[out_idx] = unsafe { *char_ptr };

            out_idx += 1;
            offset += 1;
            label_remaining -= 1;
        }
    }

    Err(())
}

/// Parses the DNS Answer section RDATA payload to extract resolved IPv4 / IPv6 addresses.
///
/// Answer Section Wire Layout (RFC 1035 Section 4.1.3):
/// +---------------------------------------------------+
/// | NAME     (2 bytes)  - Compression Pointer \xC0\x0C|
/// | TYPE     (2 bytes)  - 0x0001 (A) or 0x001C (AAAA) |
/// | CLASS    (2 bytes)  - 0x0001 (IN - Internet)      |
/// | TTL      (4 bytes)  - Time-To-Live                |
/// | RDLENGTH (2 bytes)  - Payload length (4 or 16)    |
/// | RDATA    (N bytes)  - Raw IP address bytes        |
/// +---------------------------------------------------+
#[inline(always)]
fn parse_rdata(ctx: &TcContext, mut offset: usize, event: &mut DnsEvent) -> Result<i32, ()> {
    // Inspect Answer NAME byte: Compression Pointer (0xC0XX) is 2 bytes
    let name_byte = unsafe { *ptr_at::<u8>(ctx, offset)? };
    if (name_byte & 0xC0) == 0xC0 {
        offset += 2;
    } else {
        // Fallback for uncompressed name in Answer section
        offset = parse_qname(ctx, offset, event)?;
    }

    // Read TYPE (2B)
    let type_ptr: *const u16 = unsafe { ptr_at(ctx, offset)? };
    let rtype = u16::from_be(unsafe { *type_ptr });

    // Read RDLENGTH (at offset + 8, after TYPE(2B) + CLASS(2B) + TTL(4B))
    let rdlength_ptr: *const u16 = unsafe { ptr_at(ctx, offset + 8)? };
    let rdlength = u16::from_be(unsafe { *rdlength_ptr });

    // Skip TYPE (2B) + CLASS (2B) + TTL (4B) + RDLENGTH (2B) = 10 bytes to reach RDATA
    offset += 10;

    match rtype {
        IpAddress::DNS_V4 if rdlength == 4 => {
            let addr_ptr: *const [u8; 4] = unsafe { ptr_at(ctx, offset)? };
            event.resolved_ip = IpAddress::V4(unsafe { *addr_ptr });
        }
        IpAddress::DNS_V6 if rdlength == 16 => {
            let addr_ptr: *const [u8; 16] = unsafe { ptr_at(ctx, offset)? };
            event.resolved_ip = IpAddress::V6(unsafe { *addr_ptr });
        }
        _ => {
            event.resolved_ip = IpAddress::Unknown;
        }
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
