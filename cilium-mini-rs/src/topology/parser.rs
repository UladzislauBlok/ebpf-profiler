// #[derive(Clone, Copy)]
// pub struct DnsHdr {
//     pub transaction_id: u16,
//     pub flags: u16,
//     pub questions: u16,
//     pub answer_rrs: u16,
//     pub authority_rrs: u16,
//     pub additional_rrs: u16,
// }

// impl DnsHdr {
//     /// The size of the DNS header in bytes (12 bytes).
//     pub const LEN: usize = mem::size_of::<DnsHdr>();
// }
// impl RawIpAddr {
//     /// DNS Resource Record TYPE 1 (0x0001): A Record (IPv4 Address)
//     /// Reference: RFC 1035 Section 3.2.2 (https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2)
//     pub const DNS_V4: u16 = 0x0001;

//     /// DNS Resource Record TYPE 28 (0x001C): AAAA Record (IPv6 Address)
//     /// Reference: RFC 3596 Section 2.1 (https://datatracker.ietf.org/doc/html/rfc3596#section-2.1)
//     pub const DNS_V6: u16 = 0x001C;
// }
// fn f() {
//     // QNAME  - n bytes
//     // QTYPE  - 2 bytes
//     // QCLASS - 2 bytes
//     offset = parse_qname(ctx, offset + DnsHdr::LEN, event)? + 4;

//     parse_rdata(ctx, offset, event)?;
// }

// /// Parses variable-length length-prefixed DNS domain labels (`QNAME`) from the Question section.
// ///
// /// Question Section Wire Layout (RFC 1035 Section 4.1.2):
// /// +---------------------------------------------------+
// /// | QNAME  (Variable: length-prefixed domain labels) |
// /// |        e.g. \x03www\x06google\x03com\x00           |
// /// +---------------------------------------------------+
// /// | QTYPE  (2 bytes) - 0x0001 (A), 0x001C (AAAA), etc.|
// /// +---------------------------------------------------+
// /// | QCLASS (2 bytes) - 0x0001 (IN - Internet)         |
// /// +---------------------------------------------------+
// ///
// /// Label Encoding:
// /// - Each domain label starts with a 1-byte length prefix (0x01 to 0x3F).
// /// - QNAME terminates with a null byte (0x00).
// /// - Dot separators ('.') are inserted between labels into `event.domain_name`.
// #[inline(always)]
// fn parse_qname(ctx: &TcContext, mut offset: usize, event: &mut DnsEvent) -> Result<usize, ()> {
//     let mut out_idx: usize = 0;
//     let mut label_remaining: usize = 0;

//     for _ in 0..256 {
//         if label_remaining == 0 {
//             // Read 1-byte label length
//             let len_ptr: *const u8 = unsafe { ptr_at(ctx, offset)? };
//             let label_len = unsafe { *len_ptr } as usize;
//             offset += 1;

//             // 0x00 indicates end of QNAME
//             if label_len == 0 {
//                 event.domain_len = out_idx as u32;
//                 return Ok(offset);
//             }

//             // https://datatracker.ietf.org/doc/html/rfc1035
//             // RFC 1035: Label length cannot exceed 63 bytes
//             if label_len > 63 {
//                 return Err(());
//             }

//             // Add dot separator between labels (e.g. "www" -> "www.")
//             if out_idx > 0 && out_idx < 256 {
//                 event.domain_name[out_idx] = b'.';
//                 out_idx += 1;
//             }

//             label_remaining = label_len;
//         } else {
//             if out_idx >= 256 {
//                 return Err(());
//             }

//             let char_ptr: *const u8 = unsafe { ptr_at(ctx, offset)? };
//             event.domain_name[out_idx] = unsafe { *char_ptr };

//             out_idx += 1;
//             offset += 1;
//             label_remaining -= 1;
//         }
//     }

//     Err(())
// }

// /// Parses the DNS Answer section RDATA payload to extract resolved IPv4 / IPv6 addresses.
// ///
// /// Answer Section Wire Layout (RFC 1035 Section 4.1.3):
// /// +---------------------------------------------------+
// /// | NAME     (2 bytes)  - Compression Pointer \xC0\x0C|
// /// | TYPE     (2 bytes)  - 0x0001 (A) or 0x001C (AAAA) |
// /// | CLASS    (2 bytes)  - 0x0001 (IN - Internet)      |
// /// | TTL      (4 bytes)  - Time-To-Live                |
// /// | RDLENGTH (2 bytes)  - Payload length (4 or 16)    |
// /// | RDATA    (N bytes)  - Raw IP address bytes        |
// /// +---------------------------------------------------+
// #[inline(always)]
// fn parse_rdata(ctx: &TcContext, mut offset: usize, event: &mut DnsEvent) -> Result<i32, ()> {
//     // Inspect Answer NAME byte: Compression Pointer (0xC0XX) is 2 bytes
//     let name_ptr: *const u8 = unsafe { ptr_at(ctx, offset)? };
//     let name_byte = unsafe { *name_ptr } as u8;
//     if (name_byte & 0xC0) == 0xC0 {
//         offset += 2;
//     } else {
//         // Fallback for uncompressed name in Answer section
//         offset = parse_qname(ctx, offset, event)?;
//     }

//     // Read TYPE (2B)
//     let type_ptr: *const u16 = unsafe { ptr_at(ctx, offset)? };
//     let rtype = u16::from_be(unsafe { *type_ptr });

//     // Read RDLENGTH (at offset + 8, after TYPE(2B) + CLASS(2B) + TTL(4B))
//     let rdlength_ptr: *const u16 = unsafe { ptr_at(ctx, offset + 8)? };
//     let rdlength = u16::from_be(unsafe { *rdlength_ptr });

//     // Skip TYPE (2B) + CLASS (2B) + TTL (4B) + RDLENGTH (2B) = 10 bytes to reach RDATA
//     offset += 10;

//     match rtype {
//         IpAddress::DNS_V4 if rdlength == 4 => {
//             let addr_ptr: *const [u8; 4] = unsafe { ptr_at(ctx, offset)? };
//             event.resolved_ip = IpAddress::V4(unsafe { *addr_ptr });
//         }
//         IpAddress::DNS_V6 if rdlength == 16 => {
//             let addr_ptr: *const [u8; 16] = unsafe { ptr_at(ctx, offset)? };
//             event.resolved_ip = IpAddress::V6(unsafe { *addr_ptr });
//         }
//         _ => {
//             event.resolved_ip = IpAddress::Unknown;
//         }
//     }

//     Ok(TC_ACT_OK)
// }
