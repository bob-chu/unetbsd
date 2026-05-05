# Multi-Core RSS Design Document

## 1. Overview
The goal of this design is to implement a high-performance, true multi-core architecture for the `unetbsd` user-space TCP/IP stack. By replacing the software load balancer (Primary process) with hardware-accelerated Receive Side Scaling (RSS), we eliminate the Core 0 bottleneck and reduce inter-process communication latency to zero for standard TCP traffic.

## 2. Core Architecture: Symmetric RSS
To ensure that a specific TCP connection (a 4-tuple of SrcIP, DstIP, SrcPort, DstPort) is processed by the same core on both the client and server sides, we will employ **Symmetric Toeplitz RSS**.

### 2.1 The Symmetric Key
We will hardcode a standard 40-byte symmetric key in both the client and server applications. This key guarantees that `hash(A, B)` equals `hash(B, A)`.

```c
static uint8_t rss_symmetric_key[40] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};
```

### 2.2 Hardware Configuration (Leader Process)
The first process launched (Process ID 0) will act as the "Leader." Its responsibilities include:
1.  Initializing the DPDK EAL.
2.  Configuring the NIC port (`rte_eth_dev_configure`) with `RTE_ETH_MQ_RX_RSS` enabled and the `rss_key` pointing to the symmetric key above.
3.  Configuring the **Redirection Table (RETA)** using `rte_eth_dev_rss_reta_update`. If $N$ processes are active, the RETA must be explicitly mapped such that all hash buckets point only to queues $0$ through $N-1$.

## 3. Client-Side Port Affinity (Precalculated Port Hunting)
Since the server binds to a fixed port (e.g., 8000), the client must carefully select its source ports. If a client on Core 2 chooses a source port that the hardware hashes to Core 1, the connection will fail (TCP RST) because the state exists on the wrong core.

### 3.1 Preallocation via Software Hash
During `tcp_layer_init_local_port_pool` (executed once at startup, before any traffic flows), the client will use `rte_softrss_be` (or an equivalent software implementation of the Toeplitz hash) to perfectly simulate the NIC's RSS behavior.

### 3.2 Port Pool Generation
The precalculation follows this logic:
1.  Iterate through the entire configured source port range (e.g., 1024 to 65000).
2.  For each candidate port, construct the 4-tuple and calculate the hash using the symmetric key.
3.  Calculate the target queue: `QueueID = Hash % TotalProcs`. (Assuming a linear RETA mapping).
4.  If `QueueID == MyProcID`, add the port to the local `g_local_ports` array.
5.  This preallocated pool guarantees that every connection initiated by Process $X$ will naturally hash back to Hardware Queue $X$ on both the client and server NICs without any runtime calculation overhead.

## 4. Control Plane: ARP Shadow Rings
ARP packets (and potentially ICMP) are broadcast or un-hashed traffic. If Process 1 receives an ARP request for the shared IP, Process 2 will not see it, leading to incomplete ARP tables.

### 4.1 Shadow Ring Initialization
The Leader process will create $N$ DPDK rings (`rte_ring_create`) named `ARP_RING_0`, `ARP_RING_1`, etc. Secondary processes will look up these rings.

### 4.2 Packet Cloning and Broadcast
In `port_read` (the DPDK RX loop):
1.  If an incoming mbuf is identified as an ARP packet (`RTE_ETHER_TYPE_ARP`).
2.  The receiving process clones the mbuf $N-1$ times using `rte_pktmbuf_clone`.
3.  The clones are enqueued to every other process's `ARP_RING_X`.

### 4.3 Shadow Ring Consumption
At the beginning of every event loop iteration, before checking the hardware RX queue, each process will call `rte_ring_dequeue_burst` on its designated `ARP_RING_X`. Any packets found are injected into the local NetBSD stack instance.

## 5. Memory Isolation (Private Mbuf Pools)
To maximize cache locality and eliminate cross-core lock contention during high-speed TX/RX operations:
1.  The Leader creates $N$ distinct mempools (`MBUF_POOL_0`, `MBUF_POOL_1`, etc.).
2.  During `rte_eth_rx_queue_setup`, Queue $X$ is explicitly bound to `MBUF_POOL_X`.
3.  When an ARP packet is cloned, DPDK's reference counting ensures that when Process $Y$ frees a packet originating from `MBUF_POOL_X`, the memory is correctly returned to Pool $X$.

## 6. Execution Model
The `perf_tool` will accept two new parameters:
*   `--total-procs <N>`: The total number of processes participating in the cluster.
*   `--proc-id <X>`: The unique identifier for this specific process ($0$ to $N-1$).

Process 0 must be launched first. Subsequent processes (1 to N-1) are launched as DPDK secondary processes (`--proc-type=secondary`) and attach to the shared hardware queues and memory zones established by Process 0.
