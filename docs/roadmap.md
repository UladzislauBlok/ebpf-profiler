# Roadmap

## Phase 1 — Multiple probes and richer maps

1. **Add `tcp_sendmsg` kretprobe (bytes sent)**
   - _Learns:_ managing multiple eBPF programs from one user-space loader, separate maps per probe
   - _Metrics:_ `bytes_received_total`, `bytes_sent_total`

2. **Add `udp_recvmsg` / `udp_sendmsg` probes**
   - _Learns:_ scaling the pattern from step 1, organizing eBPF code across protocols
   - _Metrics:_ `tcp_bytes_in`, `tcp_bytes_out`, `udp_bytes_in`, `udp_bytes_out`

3. **Track per-PID using `bpf_get_current_pid_tgid()`**
   - _Learns:_ eBPF helper functions, `HashMap` with dynamic keys (not just key=0), iterating maps from user-space, Prometheus labels
   - _Metrics:_ all above, but labeled by `{pid="1234", comm="curl"}`

## Phase 2 — Connection lifecycle

4. **Track new connections via `tcp_v4_connect` / `inet_csk_accept`**
   - _Learns:_ kprobes (not just kretprobes), reading function arguments from `ProbeContext`, difference between counters and gauges in Prometheus
   - _Metrics:_ `tcp_connections_total`, `tcp_active_connections`

5. **Track connection close via `tcp_close`**
   - _Learns:_ correlating events across probes (connect → close), eBPF map as state store (track active connections by decrementing on close)
   - _Metrics:_ `tcp_active_connections` becomes a live gauge

## Phase 3 — Events and ring buffers

6. **Send per-connection events to user-space via `RingBuf`**
   - _Learns:_ eBPF ring buffers (replacing map polling with event streaming), defining richer event structs in `common`, async event consumption in tokio
   - _Result:_ real-time connection event log instead of aggregated counters

7. **Add source/destination IP and port to events**
   - _Learns:_ reading `struct sock` fields from eBPF context, working with `core::net` types in no_std, network byte order (`u16::from_be`)
   - _Metrics:_ traffic breakdowns by destination (e.g., top 10 IPs by bytes)

## Phase 4 — XDP (raw packet access)

8. **Write your first XDP program (packet counter)**
   - _Learns:_ XDP program type, `XdpContext`, packet bounds checking (the eBPF verifier is strict here), `XDP_PASS`/`XDP_DROP` return codes
   - _Metrics:_ `packets_total` at the network interface level

9. **Parse Ethernet + IP headers in XDP**
   - _Learns:_ raw pointer arithmetic in eBPF, verifier-safe bounds checks, `#[repr(C)]` structs matching kernel headers, no_std byte parsing
   - _Metrics:_ `packets_by_protocol {proto="tcp"}`, `packets_by_protocol {proto="udp"}`

10. **Parse TCP/UDP headers, track by port**
    - _Learns:_ layered protocol parsing, combining XDP (fast packet-level) with kprobes (connection-level) for a complete picture
    - _Metrics:_ `bytes_by_port {port="443"}`, `bytes_by_port {port="53"}`

## Phase 5 — Production hardening (Rust focus)

11. **Graceful shutdown with `tokio::select!`**
    - _Learns:_ `select!` macro, cancellation safety, structured concurrency in tokio, cleaning up eBPF programs on exit

12. **Configuration via a TOML file (using `serde`)**
    - _Learns:_ `serde` deserialization, the `config` crate pattern, separating runtime config from code

13. **Integration tests using `aya-test` or network namespaces**
    - _Learns:_ testing eBPF programs, Linux network namespaces, writing async tests in tokio
