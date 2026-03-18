#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kretprobe, map},
    maps::PerCpuHashMap,
    programs::RetProbeContext,
};
use aya_log_ebpf::error;
use packet_watcher_rs_common::PacketStats;

#[map]
static BYTES_PER_CPU: PerCpuHashMap<u32, PacketStats> =
    PerCpuHashMap::<u32, PacketStats>::with_max_entries(32, 0);

#[kretprobe]
pub fn paccher_rs(ctx: RetProbeContext) -> u32 {
    match try_packet_watcher_rs(&ctx) {
        Ok(ret) => ret,
        Err(ret) => {
            error!(&ctx, "Error while reading bytes: {} from context", ret);
            ret.try_into().unwrap_or(1)
        }
    }
}

fn put_bytes(new_bytes: u64) -> Result<(), i32> {
    let key = 0;
    let mut stats = match { BYTES_PER_CPU.get_ptr_mut(&key) } {
        Some(ptr) => unsafe { *ptr },
        None => PacketStats { bytes: 0 },
    };

    stats.bytes += new_bytes;
    BYTES_PER_CPU.insert(&key, &stats, 0)
}

fn try_packet_watcher_rs(ctx: &RetProbeContext) -> Result<u32, u32> {
    let bytes = ctx.ret::<i32>();
    if bytes <= 0 {
        return Ok(0);
    }
    match put_bytes(bytes as u64) {
        Ok(()) => Ok(0),
        Err(_) => Err(1),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Aligned to 16 bytes to satisfy the BTF verifier while keeping your license text
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
