mod ingestor;

use anyhow::Context;
use aya::programs::{SchedClassifier, TcAttachType, tc};
use log::{debug, info, warn};
use packet_watcher_rs_common::RING_BUF_NAME;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit
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

    // Attach TC Program
    // Note: 'lo' (loopback) or 'eth0' can be used depending on your test environment.
    let iface = "wlan0";

    // Ensure clsact qdisc is added to the interface
    let _ = tc::qdisc_add_clsact(iface);

    let program: &mut SchedClassifier = ebpf
        .program_mut("dns_tc")
        .context("failed to find program 'dns_tc'")?
        .try_into()
        .context("failed to cast program to SchedClassifier")?;

    program.load().context("failed to load tc program")?;

    // Attach to ingress and egress
    program
        .attach(iface, TcAttachType::Ingress)
        .context("failed to attach tc ingress")?;
    program
        .attach(iface, TcAttachType::Egress)
        .context("failed to attach tc egress")?;

    info!("Attached TC program to {}", iface);

    let map = ebpf
        .take_map(RING_BUF_NAME)
        .context(format!("failed to find {} map", RING_BUF_NAME))?;

    if let Err(e) = ingestor::start(map).await {
        warn!("Ingestor error: {e:#}");
    }

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
