# Packet Watcher eBPF Architecture

This document describes the inner workings of the eBPF component of `packet-watcher-rs` and how it interacts with the Linux kernel and user space.

## Kernel Specific Details

### Probe Types

The eBPF program relies entirely on **`fexit`** (function exit) probes. These probes attach to the exit points of kernel functions. This is crucial because it allows the program to observe not only the arguments passed to the kernel functions but also their return values, which in this case represent the number of bytes successfully transmitted or received.

### Observed Kernel Functions

The program traces transport layer network events by hooking into the following kernel functions (targeted at kernel version v7.0.11):

1. **`tcp_sendmsg`**
   - **Signature**: `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`
   - **Probe**: `tcp_sendmsg_fexit`
   - **Behavior**: Retrieves the socket pointer (`sk`) from argument 0 and the returned bytes sent from the return value (argument 3 in `fexit` context).
2. **`tcp_recvmsg`**
   - **Signature**: `int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)`
   - **Probe**: `tcp_recvmsg_fexit`
   - **Behavior**: Retrieves the socket pointer (`sk`) from argument 0 and the returned bytes received from the return value (argument 5 in `fexit` context).
3. **`udp_sendmsg`**
   - **Signature**: `int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)`
   - **Probe**: `udp_sendmsg_fexit`
   - **Behavior**: Retrieves the socket pointer (`sk`) from argument 0 and the returned bytes sent from the return value (argument 3 in `fexit` context).
4. **`udp_recvmsg`**
   - **Signature**: `int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)`
   - **Probe**: `udp_recvmsg_fexit`
   - **Behavior**: Retrieves the socket pointer (`sk`) from argument 0 and the returned bytes received from the return value (argument 5 in `fexit` context).

### Socket Data Extraction

From the `struct sock` pointer, the program parses deep into kernel structures (e.g., `__sk_common`) to extract:

- **IP Family**: Determining if the connection is IPv4 (`AF_INET`) or IPv6 (`AF_INET6`).
- **IP Addresses**: Source and destination IPs.
- **Ports**: Source and destination ports (handling endianness conversion for destination ports via `u16::from_be`).

## Data Modeling

Both kernel and user space share a common data model (`packet-watcher-rs-common`) with a `#[repr(C)]` layout to guarantee stable memory alignment when passing data across the boundary.

### `PacketStats`

This is the primary event payload, sized at exactly 56 bytes (padded for 4-byte alignment). It contains:

- **`connection_info`** (`ConnectionInfo`): 46-byte struct holding connection details.
- **`bytes`** (`i32`): 4 bytes representing the bytes transferred. If the value is `< 0`, it is ignored (e.g., expected for non-blocking sockets).
- **`function`** (`u16`): 2 bytes mapping to a `WatchedFunction` enum (`TcpSendmsg`, `TcpRecvmsg`, `UdpSendmsg`, `UdpRecvmsg`).

### `ConnectionInfo` & `IpAddress`

- The `ConnectionInfo` struct holds the IP family, source/destination IPs, and ports.
- `IpAddress` is an enum (`V4`, `V6`, `Unknown`). Due to `#[repr(C)]` semantics, the enum discriminant tag takes up 4 bytes (u32), resulting in a 20-byte size for `IpAddress` overall (4 bytes tag + 16 bytes for V6 payload).

## Kernel to User Space Communication

Communication is achieved using an **eBPF Ring Buffer** (`bpf_ringbuf`). This is an efficient, lockless, MPSC (multi-producer, single-consumer) queue.

- **Map Name**: `PACKET_STATS_PIPE`
- **Sizing**:
  - Size must be a power-of-2 multiple of the system page size (typically 4096 bytes, you can run `getconf PAGE_SIZE` to verify).
  - Chosen Size: **8,388,608 bytes (8 MB)**.
  - This capacity is estimated to handle ~10,000 events/sec over 10 seconds without dropping packets, accounting for the 64-byte cost per entry (56 bytes payload + 8 bytes kernel header).
- **Process**:
  1. For every captured network event, the eBPF program calls `intercept_packet`.
  2. The data is parsed into a `PacketStats` struct.
  3. Space is reserved in the Ring Buffer.
  4. Data is written into the reserved entry.
  5. The entry is submitted (`entry.submit(0)`), waking up the user space consumer to read the event.
