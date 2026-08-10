mod ingestor;
mod parser;

use anyhow::Context;
use aya::{
    Ebpf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use clap::Parser;
use log::{info, warn};
use packet_watcher_rs_common::RING_BUF_NAME;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "eBPF Network Packet Watcher & DNS Telemetry Logger"
)]
struct Cli {
    /// Network interface to attach TC program (e.g. wlan0, eth0, lo)
    #[arg(short, long, default_value = "wlan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Cli::parse();
    let iface = &opt.iface;
    env_logger::init();

    bump_memlock_rlimit()?;

    let mut ebpf = load_ebpf()?;

    if let Err(e) = setup_ebpf_logging(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    attach_tc_program(iface, &mut ebpf)?;

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

fn load_ebpf() -> anyhow::Result<Ebpf> {
    aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/packet-watcher-rs"
    )))
    .context("failed to load eBPF object")
}

fn attach_tc_program(iface: &str, ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let _ = tc::qdisc_add_clsact(iface);

    let program: &mut SchedClassifier = ebpf
        .program_mut("dns_tc")
        .context("failed to find program 'dns_tc'")?
        .try_into()
        .context("failed to cast program to SchedClassifier")?;

    program.load().context("failed to load tc program")?;

    program
        .attach(iface, TcAttachType::Ingress)
        .context("failed to attach tc ingress")?;

    program
        .attach(iface, TcAttachType::Egress)
        .context("failed to attach tc egress")?;

    info!("Attached TC program to {}", iface);
    Ok(())
}

fn bump_memlock_rlimit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        anyhow::bail!(
            "failed to set RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn setup_ebpf_logging(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let logger = aya_log::EbpfLogger::init(ebpf).context("failed to init EbpfLogger")?;
    let mut async_fd =
        tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
            .context("failed to create AsyncFd for logger")?;

    tokio::task::spawn(async move {
        while let Ok(mut guard) = async_fd.readable_mut().await {
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });

    Ok(())
}
