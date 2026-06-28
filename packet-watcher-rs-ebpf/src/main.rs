#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, btf_map},
    programs::TcContext,
    bindings::TC_ACT_OK,
    btf_maps::RingBuf,
};
use aya_log_ebpf::info;
use packet_watcher_rs_common::DnsEvent;

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
pub fn packet_watcher_tc(ctx: TcContext) -> i32 {
    match try_packet_watcher_tc(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_packet_watcher_tc(_ctx: TcContext) -> Result<i32, i32> {
    // Phase 2: DNS Parsing and Fast-Path logic will go here.
    // For now, we instantly pass all packets.
    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
