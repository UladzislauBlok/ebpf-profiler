# Roadmap: Dataplane V2 Interview Prep (DNS & FQDN Policies)

This roadmap is tailored for a deep-dive into Kubernetes Dataplane V2 (Cilium) architecture. It abandons broad generalities to focus entirely on building a high-performance, verifier-safe DNS inspector and dynamic FQDN network policy engine using eBPF Traffic Control (TC).

## Phase 1: L4 Transport Foundations (Completed)

_Goal: Master socket-layer observability and eBPF state management. Move from global counters to connection-aware metrics._

- [x] Attach kprobes to `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, and `udp_recvmsg`.
- [x] Export basic packet and byte metrics to user-space via an HTTP endpoint.
- [x] Add `fexit` (entry hooks) to these functions to extract the 4-tuple (Source IP, Source Port, Dest IP, Dest Port) from `struct sock`.
- [x] Replace map polling with an eBPF Ring Buffer to stream "connection started" and "connection closed" events to user-space asynchronously.

## Phase 2: DNS DPI via Traffic Control (TC) & Fast-Path

_Goal: Safely parse packet payloads directly from the network interface using TC, implementing early-exits to achieve zero-overhead monitoring._

- [x] Transition to **TC (`clsact`) ingress hooks**.
- [x] Implement **Fast-Path Early Exits**: Write highly optimized header parsing (Ethernet $\to$ IP $\to$ UDP/TCP) that immediately returns `TC_ACT_OK` for any non-port-53 traffic, reducing per-packet overhead to mere nanoseconds.
- [ ] Build a verifier-safe DNS Header parser (extracting Transaction ID, Flags, Question/Answer count).
- [ ] **The Verifier Challenge**: Implement bounded loops (e.g., `#pragma unroll` equivalents in Rust) to safely parse the variable-length, length-prefixed DNS domain name labels (e.g., `[3]www[6]google[3]com[0]`) without failing the eBPF static analyzer.
- [ ] Extract resolved IP addresses from the DNS Response `Answer` section.
- [ ] Stream the extracted telemetry `(DomainName, ResolvedIP)` to user-space via the `PACKET_STATS_PIPE` Ring Buffer.

## Phase 3: Dynamic FQDN Network Policies (Dataplane V2 Core)

_Goal: Replicate Cilium's approach to domain-based network security by using DNS resolutions to dynamically populate an L3 eBPF firewall._

- [ ] Create an eBPF Hash Map (`ALLOWED_IPS_MAP`) shared between user-space and the kernel.
- [ ] Build a user-space consumer that reads the DNS Ring Buffer. When a target domain (e.g., `api.github.com`) is resolved, insert the dynamically returned IP into the `ALLOWED_IPS_MAP`.
- [ ] Write a secondary **TC Egress** eBPF program (the Firewall).
- [ ] Implement an O(1) map lookup in the Egress program: For every outbound packet, check if the Destination IP exists in the `ALLOWED_IPS_MAP`.
- [ ] Action the Firewall: Return `TC_ACT_OK` if the IP is allowed, or `TC_ACT_SHOT` (drop) if it is unauthorized.

## Phase 4: Workload Identity & Container Attribution (GKE Integration)

_Goal: Attribute DNS requests and policy enforcements to specific Kubernetes Pods, moving from node-level to pod-level observability._

- [ ] Extract the Network Namespace (`netns`) ID from the `__sk_buff` socket buffer to identify container boundaries.
- [ ] Read `bpf_get_current_cgroup_id()` to associate the network traffic with container runtime cgroups.
- [ ] Build a user-space cache mapping cgroup/netns IDs to mock Kubernetes Pod names, enabling pod-attributed DNS logging and per-pod FQDN policies.

## Phase 5: High-Performance Dataplane (Encapsulation & XDP)

_Goal: Understand how GKE overlay networks function and drop down to the driver layer._

- [ ] Identify Encapsulation (VXLAN / Geneve / IP-in-IP) headers in raw packets to untangle GKE overlay network routing before parsing the inner DNS payloads.
- [ ] Port the TC egress/ingress logic to XDP (eXpress Data Path) for extreme line-rate dropping of blocklisted IPs before the Linux networking stack even allocates an `sk_buff`.
