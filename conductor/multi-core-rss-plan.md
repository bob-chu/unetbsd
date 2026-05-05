# Multi-Core RSS Implementation Plan

## Objective
Implement hardware-accelerated multi-core support using Symmetric RSS, private Mbuf pools, and Client-Side Port Affinity to achieve maximum throughput on the `memif` driver without a software load balancer bottleneck.

## Key Components

### 1. Symmetric RSS Configuration
*   Define a hardcoded 40-byte symmetric RSS key (e.g., the Mellanox key) in both client and server code.
*   Update the `rte_eth_conf` structure in `app/gen_if.c` to enable `RTE_ETH_MQ_RX_RSS` and configure it to use this symmetric key.
*   Configure the RSS Indirection Table (RETA) via `rte_eth_dev_rss_reta_update` in the "Leader" process to ensure traffic is only hashed to active queues ($0$ to $N-1$).

### 2. ARP Shadow Ring Broadcast
*   The "Leader" process (Queue 0) creates $N$ DPDK rings (`ARP_RING_0`, `ARP_RING_1`, etc.).
*   In `port_read`, if an ARP packet is detected, the receiving process clones it $N-1$ times using `rte_pktmbuf_clone` and enqueues it to the other processes' ARP rings.
*   Before checking the hardware queue, each process dequeues and processes any ARP packets in its dedicated shadow ring.

### 3. Client-Side Port Affinity
*   Implement a software Toeplitz hash calculation using the same 40-byte symmetric key.
*   During `tcp_layer_client_init` in `perf_tool/tcp_layer.c`, iterate through the available source port range (e.g., 1024-65000).
*   For each port, calculate `ToeplitzHash(SrcIP, DstIP, SrcPort, DstPort) % TotalCores`.
*   If the result equals the process's assigned `proc-id`, add that port to the `g_local_ports` array. This ensures the client only opens connections that the hardware will hash back to its own RX queue.

### 4. Mbuf Pool Management
*   The "Leader" process creates $N$ separate mbuf pools (`MBUF_POOL_0`, `MBUF_POOL_1`, etc.).
*   Each worker process binds exclusively to its corresponding pool and RX/TX queue to eliminate cross-core memory contention.

### 6. Docker-Based Execution Environment
*   All build and test operations are performed inside the `my-ubuntu` Docker container.
*   The project root inside the container is mapped to `/app`.
*   Build Command: `docker exec -w /app my-ubuntu bash build.sh`
*   Execution: Use `docker exec` to launch multiple instances of `perf_tool` with different `--proc-id` values.

## Verification Steps
1.  **Build:** Run the build command inside the container.
2.  **Network Setup:** Run `./net.sh` on the host to create veth pairs (if using AF_PACKET) or ensure memif sockets are accessible.
3.  **Server Launch:** Launch $N$ server processes.
    ```bash
    docker exec -d my-ubuntu /app/build/perf_tool server /app/s_native.json --proc-id 0 --total-procs 2
    docker exec -d my-ubuntu /app/build/perf_tool server /app/s_native.json --proc-id 1 --total-procs 2
    ```
4.  **Client Launch:** Launch $N$ client processes.
    ```bash
    docker exec -d my-ubuntu /app/build/perf_tool client /app/c_native.json --proc-id 0 --total-procs 2
    docker exec -d my-ubuntu /app/build/perf_tool client /app/c_native.json --proc-id 1 --total-procs 2
    ```
5.  **Metrics:** Verify that traffic is distributed across all cores using the `ptm` (Perf Tool Master) or by checking individual process logs.
