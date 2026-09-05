# cilium-mini-rs

eBPF-powered Kubernetes Dataplane V2 & Network Observability Daemon in Rust.

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Kernel Space [Linux Kernel: eBPF Datapath]
        TC["TC Ingress & Egress Hook (clsact)"]
        CLF["DNS TC Classifier"]
        TC --> CLF
        CLF -->|Filter: UDP port 53 responses| RB[("64MB eBPF Ring Buffer")]
        CLF -->|Non-DNS / Requests| PASS["Pass Packet (Zero Overhead)"]
    end

    subgraph User Space [Userspace Daemon]
        RB -->|Epoll Reactive Drain| RDR["Stage 1: eBPF Reader"]
        RDR -->|Bounded Queue: 1,000 slots| PRS["Stage 2: DNS Wire Parser"]
        PRS -->|Zero-Allocation Swap| WRT["Stage 3: Commit Log Writer"]
    end

    subgraph Storage [Disk]
        WRT -->|256KB Batched Append| LOG[("00000001.ldpb<br/>(Length-Delimited Protobuf)")]
    end
```

For detailed component documentation:

- [eBPF Datapath Architecture](docs/ebpf_architecture.md)
- [Userspace Pipeline Architecture](docs/userspace_architecture.md)

---

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
2. bpf-linker: `cargo install bpf-linker`

## Build & Run

```shell
cargo build

sudo cilium-mini-rs -i lo
```

## License

This project utilizes a split-licensing model, separating the user-space application and the kernel-space eBPF code.

### User-Space

With the exception of the eBPF code, this application is distributed under the terms of the [MIT License].

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you shall be licensed under the MIT License, without any additional terms or conditions.

### Kernel-Space

All eBPF code is distributed under the terms of either:

- The [GNU General Public License (Version 2)]
- The [MIT License]

_(at your option)._

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the GPL-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.

---

[MIT License]: LICENSE-MIT
[GNU General Public License (Version 2)]: LICENSE-GPL2
