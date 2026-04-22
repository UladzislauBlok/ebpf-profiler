# Roadmap

## Phase 1: L4 Transport Foundations

_Goal: Master socket-layer observability and eBPF state management. Move from global counters to connection-aware metrics._

- [x] Attach kprobes to `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, and `udp_recvmsg`.
      _Note:_ Hooks into the kernel functions called when applications send/receive data. I will learn basic eBPF program attachment and how to read function arguments.
- [x] Export basic packet and byte metrics to user-space via an HTTP endpoint.
      _Note:_ Gets data out of the kernel using eBPF maps and serves it. I will learn how user-space and kernel-space share data safely.
- [ ] Add `fexit` (entry hooks) to these functions to extract the 4-tuple (Source IP, Source Port, Dest IP, Dest Port) from `struct sock`.
      _Note:_ I will learn how to safely navigate kernel memory to read IP addresses.
- [ ] Transition from the global `STATS` array to a Hash Map, tracking bytes sent/received per IP/Port pair rather than globally.
      _Note:_ Moves from aggregate counts to granular, connection-specific observability.
- [ ] Replace map polling with an eBPF Ring Buffer to stream "connection started" and "connection closed" events to user-space asynchronously.
      _Note:_ Essential for high-performance, real-time event streaming without constantly locking or polling maps.

## Phase 2: Workload Identity & Container Context

_Goal: Understand how the Linux kernel isolates network traffic for containers using namespaces and cgroups._

- [ ] Extract the Network Namespace (netns) ID from `struct sock` to identify container boundaries.
      _Note:_ A Network Namespace gives a container its own isolated network stack. By reading the `netns` ID, I can definitively prove which container environment generated the traffic.
- [ ] Read cgroup IDs to attribute network traffic to specific workloads.
      _Note:_ Control Groups (cgroups) isolate resource usage. Reading the `cgroup` ID allows me to tie network activity back to the specific container runtime's workload.
- [ ] Correlate process data (PID, command name) with network socket events.
      _Note:_ Uses `bpf_get_current_comm()` to get the executable name. I will learn how to enrich raw network bytes with process-level context.
- [ ] Build a user-space cache that simulates a Container Runtime Interface, matching cgroup IDs to dummy container names for enriched metric output.
      _Note:_ Bridges the gap between raw kernel IDs and higher-level metadata.

## Phase 3: TCP Health & Node Reliability

_Goal: Move from fragile kprobes to stable tracepoints to monitor kernel TCP state._

- [ ] Hook into kernel tracepoints (e.g., `sock:inet_sock_set_state`) to monitor TCP state transitions (e.g., `ESTABLISHED`, `TIME_WAIT`).
      _Note:_ Tracepoints are stable API hooks in the kernel. I will learn the TCP state machine and how to reliably trace kernel events without relying on unstable kprobes.
- [ ] Track TCP retransmissions and packet drops to identify network congestion.
      _Note:_ Hooks into `tcp_retransmit_skb` or drop tracepoints. I will learn how to pinpoint network degradation at the kernel level before the application crashes.
- [ ] Calculate connection establishment latency (time between SYN and ACK).
      _Note:_ Measures the exact time it takes to establish a TCP connection. I will learn how to store timestamps in eBPF maps on SYN and calculate deltas when the connection completes.
- [ ] Measure Round Trip Time (srtt) directly from the kernel's `tcp_sock` structure.
      _Note:_ The kernel constantly calculates Smoothed RTT (srtt). I will learn how to navigate complex C structs in Rust to extract highly valuable performance metrics.

## Phase 4: High-Performance Dataplane (L2/L3 Parsing with XDP & TC)

_Goal: Drop down from the socket layer to the driver layer. Process raw packets at millions of packets per second._

- [ ] Write an XDP program to parse raw Ethernet, ARP, IPv4/IPv6, and ICMP headers.
      _Note:_ eXpress Data Path (XDP) runs at the driver level. I will learn verifier-safe raw pointer arithmetic and the exact byte-structure of L2 and L3 protocols.
- [ ] Implement a high-speed L3/L4 firewall.
      _Note:_ Use an eBPF map to store a "blocklist" of IPs and return `XDP_DROP` for matching packets.
- [ ] Attach an eBPF program to Traffic Control (TC) to inspect both ingress and egress traffic.
      _Note:_ TC works for both incoming and outgoing traffic. I will learn the critical differences between XDP (ingress only, driver level) and TC (ingress/egress, qdisc level).
- [ ] Identify Encapsulation (VXLAN / IP-in-IP) headers in raw packets.
      _Note:_ Overlay networks route inter-node traffic using encapsulation. I will learn how to parse the "outer" IP to find the "inner" IP.

## Phase 5: L7 Deep Packet Inspection (Protocol Analysis)

_Goal: Revisit L7 protocols now that you have full mastery of parsing raw bytes and streaming data._

- [ ] Hook into socket buffers (`sk_buff`) or use XDP/TC to read actual payload data, safely handling packet fragmentation.
      _Note:_ Moving beyond headers to the actual application data payload.
- [ ] Implement DNS parsing: Read the binary DNS header to extract the requested domain name, Query Type (A, AAAA), and Response Code.
      _Note:_ I will learn how to inspect L7 binary protocols.
- [ ] Implement basic HTTP/1.1 parsing.
      _Note:_ Detect `GET`/`POST` methods and HTTP status codes directly from the raw byte stream.
- [ ] Replace the simple HTTP endpoint with a structured Prometheus exporter (using histograms and gauges).
      _Note:_ Moves from basic text to an industry-standard metric format, fully integrating the rich telemetry gathered in previous phases.
