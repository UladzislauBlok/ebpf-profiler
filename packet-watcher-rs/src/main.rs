mod reporter;

use anyhow::Context;
use aya::programs::FExit;
use log::{debug, error, info, warn};
use packet_watcher_rs_common::{STATS_MAP_NAME, WatchedFunction};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/packet-watcher-rs"
    )))
    .context("failed to load eBPF object")?;

    let btf = aya::Btf::from_sys_fs()?;

    if let Err(e) = setup_ebpf_logging(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    for func in WatchedFunction::all() {
        let program: &mut FExit = ebpf
            .program_mut(func.fexit_func_name())
            .with_context(|| format!("failed to find program '{}'", func.fexit_func_name()))?
            .try_into()
            .context("failed to cast program to KProbe")?;

        program
            .load(func.kernel_func_name(), &btf)
            .context("failed to load kprobe")?;
        program
            .attach()
            .with_context(|| format!("failed to attach to '{}'", func.kernel_func_name()))?;

        info!("Attached probe for {}", func.kernel_func_name());
    }

    let map = ebpf
        .take_map(STATS_MAP_NAME)
        .context(format!("failed to find {} map", STATS_MAP_NAME))?;

    tokio::spawn(async move {
        if let Err(e) = reporter::run(&map).await {
            error!("Reporter task error: {e}");
        }
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn setup_ebpf_logging(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let logger = aya_log::EbpfLogger::init(ebpf).context("failed to init EbpfLogger")?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
            .context("failed to create AsyncFd for logger")?;

    tokio::task::spawn(async move {
        loop {
            if let Ok(mut guard) = async_fd.readable_mut().await {
                guard.get_inner_mut().flush();
                guard.clear_ready();
            }
        }
    });

    Ok(())
}
