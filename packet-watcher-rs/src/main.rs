mod reporter;

use anyhow::Context;
use aya::programs::KProbe;
use clap::Parser;
use log::{debug, error, info, warn};
use packet_watcher_rs_common::{DEFAULT_FUNCTION, DEFAULT_MAP_NAME, PROBE_NAME};
use tokio::signal;

#[derive(Parser)]
struct Opts {
    #[clap(short, long, default_value = DEFAULT_FUNCTION)]
    function: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
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

    if let Err(e) = setup_ebpf_logging(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut KProbe = ebpf
        .program_mut(PROBE_NAME)
        .with_context(|| format!("failed to find program '{}'", PROBE_NAME))?
        .try_into()
        .context("failed to cast program to KProbe")?;

    program.load().context("failed to load kprobe")?;
    program
        .attach(&opts.function, 0)
        .with_context(|| format!("failed to attach to '{}'", opts.function))?;

    let map = ebpf
        .take_map(DEFAULT_MAP_NAME)
        .context("failed to find BYTES_PER_CPU map")?;
    tokio::spawn(async move {
        if let Err(e) = reporter::run(&map).await {
            error!("Reporter task error: {e}");
        }
    });

    info!("Waiting for Ctrl-C... Probing {}", opts.function);
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
