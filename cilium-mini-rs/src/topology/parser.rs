use std::{
    error::Error,
    fmt::{self, Write},
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

use crate::topology::proto::DnsResponse;
use cilium_mini_common::{AF_INET, AF_INET6, RawDnsEvent, RawIpAddr};
use log::info;
use log::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsParseError {
    UnexpectedEndOfPayload,
    InvalidLabelLength(usize),
    LabelExceedsMaxLen,
    NonAsciiDomainName,
    UnsupportedAddressFamily(u32),
    FormatError,
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEndOfPayload => {
                write!(f, "Unexpected end of DNS payload (truncated packet)")
            }
            Self::InvalidLabelLength(len) => write!(f, "Invalid label length: {len} (> 63)"),
            Self::LabelExceedsMaxLen => write!(f, "Label exceeds maximum domain length (255)"),
            Self::NonAsciiDomainName => write!(f, "Non-ASCII character in domain name"),
            Self::UnsupportedAddressFamily(af) => write!(f, "Unsupported address family: {af}"),
            Self::FormatError => write!(f, "Failed to format IP address string"),
        }
    }
}

impl Error for DnsParseError {}

/// Parses raw DNS event payload into a protobuf `DnsResponse` slot.
/// Automatically clears existing slot contents to reuse buffers without reallocation.
pub fn parse_dns_into(
    raw_event: &RawDnsEvent,
    slot: &mut DnsResponse,
) -> Result<(), DnsParseError> {
    reset_slot(slot);
    parse_ip(&raw_event.src_ip, &mut slot.src_ip)?;
    parse_ip(&raw_event.dst_ip, &mut slot.dst_ip)?;

    slot.src_port = raw_event.src_port.into();
    slot.dst_port = raw_event.dst_port.into();
    slot.timestamp_ns = raw_event.timestamp_ns;

    let total_len = raw_event.payload_len as usize;
    if total_len < DnsHdr::LEN {
        return Err(DnsParseError::UnexpectedEndOfPayload);
    }

    let dns_payload = &raw_event.payload[..total_len];

    let qname_payload = &dns_payload[DnsHdr::LEN..];
    let qname_len = parse_qname(qname_payload, &mut slot.domain_name)?;

    let anscount = DnsHdr::from(dns_payload)?.answer_rrs;

    // QNAME (qname_len) + QTYPE (2B) + QCLASS (2B)
    let rdata_offset = DnsHdr::LEN + qname_len + 4;
    if rdata_offset > total_len {
        return Err(DnsParseError::UnexpectedEndOfPayload);
    }

    let rdata_payload = &dns_payload[rdata_offset..];
    parse_rdata(rdata_payload, anscount, slot)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsHdr {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answer_rrs: u16,
    authority_rrs: u16,
    additional_rrs: u16,
}

impl DnsHdr {
    const LEN: usize = mem::size_of::<Self>();

    pub fn from(payload: &[u8]) -> Result<Self, DnsParseError> {
        if payload.len() < Self::LEN {
            return Err(DnsParseError::UnexpectedEndOfPayload);
        }

        Ok(Self {
            transaction_id: u16::from_be_bytes([payload[0], payload[1]]),
            flags: u16::from_be_bytes([payload[2], payload[3]]),
            questions: u16::from_be_bytes([payload[4], payload[5]]),
            answer_rrs: u16::from_be_bytes([payload[6], payload[7]]),
            authority_rrs: u16::from_be_bytes([payload[8], payload[9]]),
            additional_rrs: u16::from_be_bytes([payload[10], payload[11]]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum RecordType {
    A = 1,
    CNAME = 5,
    AAAA = 28,
    UNSUPPORTED(u16),
}

impl TryFrom<u16> for RecordType {
    type Error = DnsParseError;

    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::A),
            5 => Ok(Self::CNAME),
            28 => Ok(Self::AAAA),
            other => Ok(Self::UNSUPPORTED(other)),
        }
    }
}

fn reset_slot(slot: &mut DnsResponse) {
    slot.src_ip.clear();
    slot.dst_ip.clear();
    slot.domain_name.clear();
    slot.resolved_ip.clear();
    slot.resolved_ip_raw.clear();
    slot.src_port = 0;
    slot.dst_port = 0;
    slot.ip_family = 0;
    slot.timestamp_ns = 0;
}

fn parse_ip(raw_ip: &RawIpAddr, out: &mut String) -> Result<(), DnsParseError> {
    match raw_ip.family {
        AF_INET => {
            let ip = Ipv4Addr::new(
                raw_ip.bytes[0],
                raw_ip.bytes[1],
                raw_ip.bytes[2],
                raw_ip.bytes[3],
            );
            write!(out, "{ip}").map_err(|_| DnsParseError::FormatError)?;
            Ok(())
        }
        AF_INET6 => {
            let ip = Ipv6Addr::from(raw_ip.bytes);
            write!(out, "{ip}").map_err(|_| DnsParseError::FormatError)?;
            Ok(())
        }
        other => Err(DnsParseError::UnsupportedAddressFamily(other)),
    }
}

/// Parses variable-length length-prefixed DNS domain labels (`QNAME`) from the Question section.
///
/// Question Section Wire Layout (RFC 1035 Section 4.1.2):
/// +---------------------------------------------------+
/// | QNAME  (Variable: length-prefixed domain labels)  |
/// |        e.g. \x03www\x06google\x03com\x00          |
/// +---------------------------------------------------+
///
/// Label Encoding:
/// - Each domain label starts with a 1-byte length prefix (0x01 to 0x3F).
/// - QNAME terminates with a null byte (0x00).
/// - Dot separators ('.') are inserted between labels into `event.domain_name`.
fn parse_qname(payload: &[u8], out: &mut String) -> Result<usize, DnsParseError> {
    if payload.is_empty() {
        return Err(DnsParseError::UnexpectedEndOfPayload);
    }
    let mut offset = 0;
    let mut total_domain_len = 0;

    while offset < payload.len() {
        let label_len = payload[offset] as usize;

        if label_len == 0 {
            return Ok(offset + 1);
        }

        if label_len > 63 {
            return Err(DnsParseError::InvalidLabelLength(label_len));
        }

        let label_start = offset + 1;
        let label_end = label_start + label_len;
        if label_end > payload.len() {
            return Err(DnsParseError::UnexpectedEndOfPayload);
        }

        total_domain_len += label_len + 1;
        if total_domain_len > 255 {
            return Err(DnsParseError::LabelExceedsMaxLen);
        }

        let label_bytes = &payload[label_start..label_end];
        if !label_bytes.is_ascii() {
            return Err(DnsParseError::NonAsciiDomainName);
        }

        if !out.is_empty() {
            out.push('.');
        }

        let label_str =
            str::from_utf8(label_bytes).map_err(|_| DnsParseError::NonAsciiDomainName)?;
        out.push_str(label_str);

        offset = label_end;
    }
    Err(DnsParseError::UnexpectedEndOfPayload)
}

/// Parses the DNS Answer section RDATA payload to extract resolved IPv4 / IPv6 addresses.
///
/// Answer Section Wire Layout (RFC 1035 Section 4.1.3):
/// +----------------------------------------------------------+
/// | NAME     (2 bytes)  - Compression Pointer 0xC0 (11000000)|
/// | TYPE     (2 bytes)  - 0x0001 (A) or 0x001C (AAAA)        |
/// | CLASS    (2 bytes)  - 0x0001 (IN - Internet)             |
/// | TTL      (4 bytes)  - Time-To-Live                       |
/// | RDLENGTH (2 bytes)  - Payload length (4 or 16)           |
/// | RDATA    (N bytes)  - Raw IP address bytes               |
/// +----------------------------------------------------------+
fn parse_rdata(payload: &[u8], anscount: u16, slot: &mut DnsResponse) -> Result<(), DnsParseError> {
    if payload.is_empty() {
        return Err(DnsParseError::UnexpectedEndOfPayload);
    }
    const RR_FIXED_HDR_LEN: usize = 10; // TYPE (2B) + CLASS (2B) + TTL (4B) + RDLENGTH (2B)
    let mut offset = 0;
    for _ in 0..anscount {
        if offset >= payload.len() {
            return Err(DnsParseError::UnexpectedEndOfPayload);
        }

        offset = skip_name(&payload[offset..])?;

        if offset + RR_FIXED_HDR_LEN > payload.len() {
            return Err(DnsParseError::UnexpectedEndOfPayload);
        }

        let rtype =
            RecordType::try_from(u16::from_be_bytes([payload[offset], payload[offset + 1]]))?;
        let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;

        offset += RR_FIXED_HDR_LEN;

        if offset + rdlength > payload.len() {
            return Err(DnsParseError::UnexpectedEndOfPayload);
        }

        let rdata = &payload[offset..offset + rdlength];

        match rtype {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(DnsParseError::UnexpectedEndOfPayload);
                }
                let ip = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                write!(slot.resolved_ip, "{ip}").map_err(|_| DnsParseError::FormatError)?;
                slot.resolved_ip_raw.extend_from_slice(&rdata[..4]);
                slot.ip_family = AF_INET;
            }
            RecordType::AAAA => {
                if rdlength != 16 {
                    return Err(DnsParseError::UnexpectedEndOfPayload);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&rdata);
                let ip = Ipv6Addr::from(octets);
                write!(slot.resolved_ip, "{ip}").map_err(|_| DnsParseError::FormatError)?;
                slot.resolved_ip_raw.extend_from_slice(&octets);
                slot.ip_family = AF_INET6;
            }
            RecordType::CNAME => {
                info!("Skipping CNAME part");
            }
            RecordType::UNSUPPORTED(type_num) => {
                warn!("Unexpected type {}", type_num);
            }
        }

        offset += rdlength;
    }
    Ok(())
}

fn skip_name(payload: &[u8]) -> Result<usize, DnsParseError> {
    // RFC 1035 Section 4.1.4
    const COMPRESSION_MASK: u8 = 0xC0;
    let mut offset = 0;
    while offset < payload.len() {
        let b = payload[offset];

        if (b & COMPRESSION_MASK) == COMPRESSION_MASK {
            if offset + 2 > payload.len() {
                return Err(DnsParseError::UnexpectedEndOfPayload);
            }
            return Ok(offset + 2);
        } else if b == 0 {
            return Ok(offset + 1);
        } else if b <= 63 {
            let label_len = b as usize;
            let next_offset = offset + 1 + label_len;
            if next_offset > payload.len() {
                return Err(DnsParseError::UnexpectedEndOfPayload);
            }
            offset = next_offset;
        } else {
            return Err(DnsParseError::InvalidLabelLength(b as usize));
        }
    }

    Err(DnsParseError::UnexpectedEndOfPayload)
}
