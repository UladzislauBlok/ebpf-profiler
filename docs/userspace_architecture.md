# User-Space Architecture: Write-Ahead Commit Log MVP

This document describes the design and architecture of the user-space component of `packet-watcher-rs`. 

The user-space system is split into two logical pipelines decoupled by an append-only commit log file on disk. This design is inspired by write-ahead logging (WAL) and message brokers like Apache Kafka.

---

## Architectural Diagram

```mermaid
graph TD
    subgraph Kernel Space
        ebpf[eBPF Program]
    end

    subgraph Ingestor Daemon [Producer]
        ringbuf[eBPF Ring Buffer: PACKET_STATS_PIPE]
        serializer[Protobuf Serializer]
        bufwriter[Buffered File Writer]
    end

    subgraph Storage [Disk]
        file[Active Log File: events.log]
    end

    subgraph Forwarder Daemon [Consumer]
        reader[Log Reader / Tailer]
        deserializer[Protobuf Deserializer]
        uploader[Telemetry Forwarder]
    end

    %% Flow
    ebpf -->|C Struct: PacketStats| ringbuf
    ringbuf -->|Read Raw Bytes| serializer
    serializer -->|Length-Prefixed Protobuf| bufwriter
    bufwriter -->|Append| file
    file -->|Read sequentially| reader
    reader -->|Deserialize| deserializer
    deserializer -->|Forward Events| uploader
```

---

## 1. Ingestor Daemon (Producer)

The Ingestor's sole responsibility is to drain the eBPF ring buffer as fast as possible and commit events to disk. By minimizing CPU operations and I/O latency, it guarantees the kernel eBPF ring buffer does not overflow.

### Key Operations
1. **Poll Ring Buffer**: Reads raw `PacketStats` bytes from `PACKET_STATS_PIPE` using an asynchronous file descriptor (`AsyncFd`) in a Tokio event loop.
2. **Translate & Serialize**: Translates the raw memory representation of the C struct into a Protobuf message, and serializes it to a byte array.
3. **Length-Prefixed Format**: Prepends the size of the serialized message as a `u32` value before appending the payload to the log file.
4. **Buffered Writing**: Uses a buffered writer (`BufWriter`) to batch writes in user-space memory before issuing the `write()` system call to the operating system.

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
* **Framing**: Each record starts with a 4-byte big-endian unsigned integer (`u32`) specifying the size of the following Protobuf message. Big-endian (network byte order) is standard for serialization binary formats.
* **Append-Only**: The log file is opened with write-append flags (`O_WRONLY | O_APPEND | O_CREAT`). The storage layer never rewrites or updates existing data.
* **Page Cache Reliance**: The Ingestor calls standard write APIs without `fsync` or `O_SYNC`. The OS caches write operations in memory (the Page Cache) and periodically flushes them to disk asynchronously. This ensures that disk latency does not block packet monitoring.

---

## 3. Forwarder Daemon (Consumer)

The Forwarder runs independently. It reads the commit log, deserializes the Protobuf payloads, and sends the telemetry data to external targets (e.g., standard output, Prometheus, or a remote API).

### Key Operations
1. **Sequential Scan**: Reads from the active log file starting from byte offset `0` (or a saved offset).
2. **Framing Parser**:
   * Reads exactly `4` bytes to parse the payload size $N$.
   * Reads exactly $N$ bytes to fetch the serialized Protobuf message.
3. **Tailing Behavior**:
   * If the Forwarder encounters an EOF (End of File) because it caught up to the Ingestor, it enters a polling phase.
   * It uses a short sleep interval or file change notifications (e.g., `inotify`) to wait for more data to be appended before resuming the read.

---

## 4. MVP Scope and Future Roadmap

This architecture is optimized for initial simplicity and high performance (MVP) while leaving room for production refinement.

### MVP Limitations
* **Single Log File**: The ingestor writes to a single file (e.g., `events.log`). File rotation is omitted from the MVP.
* **In-Memory Offset**: The forwarder keeps its read position in memory. If restarted, it will replay the log from the beginning.

### Planned Extensions
* **Log Segmentation & Rotation**: Closing the active segment and starting a new one when file size exceeds a threshold (e.g., 50MB).
* **Retention Policy**: Automatically deleting old, inactive segments to avoid running out of disk space.
* **Offset Checkpointing**: Periodically persisting the consumer's read byte offset to a state file on disk (e.g., `forwarder.offset`) to survive restarts.
