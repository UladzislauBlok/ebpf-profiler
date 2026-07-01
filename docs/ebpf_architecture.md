# Packet Watcher eBPF Architecture

This document describes the inner workings of the eBPF component of `packet-watcher-rs` and how it interacts with the Linux kernel and user space.

## Kernel Specific Details

### Hook Types

The eBPF program attaches to the network interface using **Traffic Control (TC) ingress and egress classifier hooks** (`SchedClassifier`). Using TC filters allows the program to inspect network traffic passing through the interface (e.g. `lo` or `eth0`) at the packet level, which is ideal for monitoring and filtering DNS traffic.

### Observed Hooks

The TC classifier hooks into the interface and routes packets to:

* **`packet_watcher_tc`** ([packet-watcher-rs-ebpf/src/main.rs](file:///workspace/rust/packet-watcher-rs/packet-watcher-rs-ebpf/src/main.rs)):
  - **Hook Type**: `classifier`
  - **Behavior**: Evaluates incoming (ingress) and outgoing (egress) packets. In Phase 2, it will parse variable-length DNS messages to extract queries/responses, and stream the metadata to user-space.

### DNS Parsing and Early Exits (Fast-Path)

To maintain low latency, the eBPF program implements early-exits:
1. Parse L2 Ethernet header to verify L3 IPv4 (`ETH_P_IP`) or IPv6 (`ETH_P_IPV6`).
2. Parse L3 IP header to verify L4 UDP or TCP.
3. Parse L4 transport header to verify DNS traffic (source or destination port is `53`).
4. Instantly return `TC_ACT_OK` for non-DNS packets, reducing overhead for unrelated traffic to a minimum.

## Data Modeling

Both kernel and user space share a common data model ([packet-watcher-rs-common/src/lib.rs](file:///workspace/rust/packet-watcher-rs/packet-watcher-rs-common/src/lib.rs)) with a `#[repr(C)]` layout to guarantee stable memory alignment when passing data across the boundary.

### `DnsEvent`

This is the primary event payload, sized at exactly 328 bytes (padded for alignment). It contains:

* **`src_ip`** (`IpAddress`): 20 bytes representing source IP.
* **`dst_ip`** (`IpAddress`): 20 bytes representing destination IP.
* **`src_port`** (`u16`): 2 bytes representing source port.
* **`dst_port`** (`u16`): 2 bytes representing destination port.
* **`domain_name`** (`[u8; 256]`): 256 bytes storing the parsed variable-length DNS domain name labels.
* **`domain_len`** (`u32`): 4 bytes specifying actual length of the domain name.
* **`resolved_ip`** (`IpAddress`): 20 bytes containing the resolved IP if the packet is a DNS response.
* **`is_response`** (`u8`): 1 byte flag (1 if response, 0 if request).

### `IpAddress`

* The `IpAddress` enum is represented as `V4([u8; 4])`, `V6([u8; 16])`, or `Unknown`. Due to `#[repr(C)]` semantics, the enum discriminant tag takes up 4 bytes (u32), resulting in a 20-byte size for `IpAddress` overall (4 bytes tag + 16 bytes payload).

## Kernel to User Space Communication

Communication is achieved using an **eBPF Ring Buffer** (`bpf_ringbuf`). This is an efficient, lockless, MPSC (multi-producer, single-consumer) queue.

* **Map Name**: `DNS_EVENTS_PIPE`
* **Sizing**:
  - Size must be a power-of-2 multiple of the system page size (typically 4096 bytes).
  - Chosen Size: **67,108,864 bytes (64 MB)**.
  - Sizing Calculation: At ~10,000 events/sec, with an entry size of 336 bytes (328 bytes payload + 8 bytes kernel header), a 64 MB ring buffer can hold up to ~10 seconds of backlogged telemetry events without dropping packets.
* **Process**:
  1. For every captured DNS packet, the eBPF program parses the protocol headers into a `DnsEvent` struct.
  2. Space is reserved in the `DNS_EVENTS_PIPE` ring buffer.
  3. Data is written into the reserved entry.
  4. The entry is submitted, waking up the user space consumer to read the event.

