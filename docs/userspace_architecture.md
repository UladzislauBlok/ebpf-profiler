# User-Space Architecture: Write-Ahead Commit Log MVP

This document describes the design and architecture of the user-space component of `packet-watcher-rs`.

The user-space system is split into two logical pipelines decoupled by an append-only commit log file on disk. This design is inspired by write-ahead logging (WAL) and message brokers like Apache Kafka.

---

## Architectural Diagram

```mermaid
    sequenceDiagram
        autonumber
        participant Pod as Application Pod Container
        participant Kernel as Linux Kernel (eBPF Redirect & TC Egress)
        participant Proxy as Cilium User-Space DNS Proxy
        participant Upstream as CoreDNS / Upstream DNS
        participant Map as BPF Map (ALLOWED_IPS_MAP)

        Note over Pod,Upstream: STAGE 1: DNS QUERY REDIRECTION
        Pod->>Kernel: 1. Send DNS Query (UDP port 53 for api.github.com)
        Kernel->>Proxy: 2. eBPF Redirects Query to Local DNS Proxy Socket
        Proxy->>Upstream: 3. Proxy Forwards Query to CoreDNS

        Note over Pod,Upstream: STAGE 2: DNS ANSWER HOLDING & SYNCHRONOUS MAP UPDATE
        Upstream-->>Proxy: 4. CoreDNS Returns DNS Answer (IP: 140.82.121.4)

        rect rgb(255, 240, 220)
            Note over Proxy: ⚠️ PROXY HOLDS DNS ANSWER IN MEMORY!<br/>DOES NOT SEND TO POD YET!
         end

         Proxy->>Proxy: 5. Parse DNS Answer (Domain: api.github.com -> 140.82.121.4)
         Proxy->>Map: 6. bpf(BPF_MAP_UPDATE_ELEM) Syscall (Insert 140.82.121.4)
         Map-->>Proxy: 7. Kernel Confirms Map Update Success!

         Note over Pod,Upstream: STAGE 3: DNS ANSWER RELEASE & RACE-FREE EGRESS FIREWALL
         rect rgb(220, 255, 220)
             Proxy-->>Pod: 8. Proxy Delivers DNS Answer to Pod Socket
         end

         Pod->>Kernel: 9. Pod Sends HTTP Request to 140.82.121.4
         Kernel->>Map: 10. TC Egress Lookup for 140.82.121.4
         Map-->>Kernel: 11. Match Found! (Allowed)
         Kernel-->>Pod: 12. Return TC_ACT_OK -> Packet Sent Out!

```

```mermaid
graph TD
    subgraph Kernel Space
        ebpf[eBPF Program]
    end

    subgraph Ingestor Daemon [Producer]
        ringbuf[eBPF Ring Buffer: DNS_EVENTS_PIPE]
        async_reader[Tokio Async Reader Task]
        mpsc[mpsc::channel 100k buffer]
        os_thread[Dedicated File Writer Thread]
        serializer[Protobuf Serializer]
        bufwriter[Buffered File Writer]
    end

    subgraph Storage [Disk]
        file[Active Log File: 00000001.ldpb]
    end

    subgraph Forwarder Daemon [Consumer]
        reader[Log Reader / Tailer]
        deserializer[Protobuf Deserializer]
        uploader[Telemetry Forwarder]
    end

    %% Flow
    ebpf -->|C Struct: DnsEvent| ringbuf
    ringbuf -->|Async poll & read| async_reader
    async_reader -->|read_unaligned & try_send Struct| mpsc
    mpsc -->|blocking_recv Struct| os_thread
    os_thread -->|convert| serializer
    serializer -->|Length-Prefixed Protobuf| bufwriter
    bufwriter -->|Append| file
    file -->|Read sequentially| reader
    reader -->|Deserialize| deserializer
    deserializer -->|Forward Events| uploader
```

---

## 1. Ingestor Daemon (Producer)

The Ingestor's sole responsibility is to drain the eBPF ring buffer as fast as possible and commit events to disk. By minimizing CPU operations and I/O latency, it guarantees the kernel eBPF ring buffer does not overflow. See the implementation in [packet-watcher-rs/src/ingestor.rs](file:///workspace/rust/packet-watcher-rs/packet-watcher-rs/src/ingestor.rs).

### Key Operations

1. **Asynchronous Ring Buffer Polling & Zero-Allocation**: A Tokio async task reads raw byte slices from the `DNS_EVENTS_PIPE` using an asynchronous file descriptor (`AsyncFd`). To avoid slow heap allocations (`malloc`), it immediately and safely transforms these unaligned chunks into `DnsEvent` structs on the stack using `std::ptr::read_unaligned`.
2. **Buffering**: These stack-allocated structs are sent into a high-capacity multi-producer single-consumer (`mpsc`) channel. Because the channel buffer is pre-allocated on startup, sending the fixed-size struct over the channel requires zero new heap allocations, maximizing packet processing speed.
3. **Dedicated I/O Thread**: A dedicated OS thread consumes the `mpsc` channel. This decoupling prevents slow disk I/O and Protobuf serialization from blocking the fast async eBPF reader.
4. **Translate & Serialize**: Converts the safely read memory representation of the C struct into a Protobuf message (`DnsEvent` defined in [proto/network_event.proto](file:///workspace/rust/packet-watcher-rs/proto/network_event.proto)), and serializes it to a pre-allocated, reusable byte array to minimize heap allocations.
5. **Length-Prefixed Format & Buffered Writing**: Prepends the size of the serialized message as a Big-Endian `u32` value (Length-Delimited format). It uses a large `BufWriter` (e.g., 256KB) to batch these user-space writes before committing them to disk via system calls, drastically reducing I/O overhead.

---

## 2. Storage Format (Commit Log)

The log file is structured as a sequential stream of length-prefixed binary messages. This format enables high-performance writes and simple, boundary-safe parsing.

```
+------------------+-----------------------+------------------+-----------------------+
|  u32 Length (N)  |  Protobuf Data Block  |  u32 Length (M)  |  Protobuf Data Block  |
|  (4 bytes, BE)   |       (N bytes)       |  (4 bytes, BE)   |       (M bytes)       |
+------------------+-----------------------+------------------+-----------------------+
```

### Technical Details

- **Framing**: Each record starts with a 4-byte big-endian unsigned integer (`u32`) specifying the size of the following Protobuf message. Big-endian (network byte order) is standard for serialization binary formats.
- **Append-Only**: The log file is opened with write-append flags (`O_WRONLY | O_APPEND | O_CREAT`) and named `00000001.ldpb` (Length-Delimited Protocol Buffers). The storage layer never rewrites or updates existing data.
- **Page Cache Reliance**: The Ingestor calls standard write APIs without `fsync` or `O_SYNC`. The OS caches write operations in memory (the Page Cache) and periodically flushes them to disk asynchronously. This ensures that disk latency does not block packet monitoring.

---

## 3. Forwarder Daemon (Consumer)

The Forwarder runs independently. It reads the commit log, deserializes the Protobuf payloads, and sends the telemetry data to external targets (e.g., standard output, Prometheus, or a remote API).

### Key Operations

1. **Sequential Scan**: Reads from the active log file starting from byte offset `0` (or a saved offset).
2. **Framing Parser**:
   - Reads exactly `4` bytes to parse the payload size $N$.
   - Reads exactly $N$ bytes to fetch the serialized Protobuf message.
3. **Tailing Behavior**:
   - If the Forwarder encounters an EOF (End of File) because it caught up to the Ingestor, it enters a polling phase.
   - It uses a short sleep interval or file change notifications (e.g., `inotify`) to wait for more data to be appended before resuming the read.

---

## 4. MVP Scope and Future Roadmap

This architecture is optimized for initial simplicity and high performance (MVP) while leaving room for production refinement.

### MVP Limitations

- **Single Log File**: The ingestor writes to a single file (e.g., `00000001.ldpb`). File rotation is omitted from the MVP.
- **In-Memory Offset**: The forwarder keeps its read position in memory. If restarted, it will replay the log from the beginning.

### Planned Extensions

- **Log Segmentation & Rotation**: Closing the active segment and starting a new one when file size exceeds a threshold (e.g., 50MB).
- **Retention Policy**: Automatically deleting old, inactive segments to avoid running out of disk space.
- **Offset Checkpointing**: Periodically persisting the consumer's read byte offset to a state file on disk (e.g., `forwarder.offset`) to survive restarts.
- **Parallel Serialization**: Protobuf encoding is a CPU-intensive path. To improve throughput under extreme load, the pipeline could use a thread pool to distribute the serialization workload across `N` threads. These threads would encode the packets in parallel and then send the serialized byte arrays into a single `mpsc` channel connected to the dedicated file writer thread, effectively parallelizing CPU-heavy work while keeping disk I/O strictly sequential.
