#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kretprobe, map},
    maps::PerCpuArray,
    programs::RetProbeContext,
};
use aya_log_ebpf::error;
use packet_watcher_rs_common::PacketStats;

#[map]
static BYTES_PER_CPU: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

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

fn put_bytes(new_bytes: u64) -> Result<(), ()> {
    let stats = BYTES_PER_CPU.get_ptr_mut(0).ok_or(())?;
    unsafe { (*stats).bytes += new_bytes };
    Ok(())
}

fn try_packet_watcher_rs(ctx: &RetProbeContext) -> Result<u32, u32> {
    let bytes = ctx.ret::<i32>();
    if bytes <= 0 {
        return Ok(0);
    }
    put_bytes(bytes as u64).map_err(|()| 1u32)?;
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
