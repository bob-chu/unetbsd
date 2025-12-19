# Performance Test Configuration (1 Client, 1 Server with Memif)

This document outlines the configuration for a performance test using a `memif` (shared memory) interface. It measures the throughput of HTTP requests between a single client and server in a DPDK-based environment.

The setup consists of one HTTP client, one HTTP server, and two load balancers communicating over a memif interface.

## Network Diagram

The following diagram illustrates the network topology of the performance test.

```
+---------------------------------------------------------------------------------+
|                                  Host Machine                                   |
|                                                                                 |
|   +---------------------------+                           +---------------------------+
|   |      Client-Side          |                           |        Server-Side          |
|   |                           |                           |                           |
|   |  +---------------------+  |         +-------+         |  +---------------------+  |
|   |  |   HTTP Client 1     |  |         |       |         |  |   HTTP Server 1     |  |
|   |  |   (c.json)          |  |         |       |         |  |   (s.json)          |  |
|   |  | Core 2              |  |         |       |         |  | Core 3              |  |
|   |  | IPs: 192.168.1.10-17|  |         |       |         |  | IPs: 192.168.1.100-107|  |
|   |  +----------^----------+  |         |       |         |  +----------^----------+  |
|   |             | (to/from)  |         |       |         |             | (to/from) |
|   |  +----------v----------+  |         | memif |         |  +----------v----------+  |
|   |  | Load Balancer (LB_C)|<----------| link  |---------->| Load Balancer (LB_S)|  |
|   |  |   (lb_c.json)       |  |         |       |         |  |   (lb_s.json)       |  |
|   |  | Core 4 (Slave)      |  |         |       |         |  | Core 5 (Master)     |  |
|   |  | Interface: memif1   |  |         |       |         |  | Interface: memif0   |  |
|   |  +---------------------+  |         +-------+         |  +---------------------+  |
|   |                           |                           |                           |
|   +---------------------------+                           +---------------------------+
|                                                                                 |
+---------------------------------------------------------------------------------+
```

## Components

### Load Balancers (lb_c.json, lb_s.json)
- **`lb_s.json`**: The server-side load balancer. It runs on `Core 5` and creates the `memif` interface as a **master**. It is responsible for forwarding packets to the HTTP server.
- **`lb_c.json`**: The client-side load balancer. It runs on `Core 4` and connects to the `memif` interface as a **slave**. It routes packets from the HTTP client.

### HTTP Client (c.json)
- **`c.json`**: Configures the HTTP client instance, running on `Core 2`. It attaches as a secondary process to the client-side load balancer.

### HTTP Server (s.json)
- **`s.json`**: Configures the HTTP server instance, running on `Core 3`. It attaches as a secondary process to the server-side load balancer.

## Network Topology
The test utilizes a **memif (shared memory)** interface, which provides a high-speed communication channel between the two load balancer processes.
- The **server-side** load balancer (`lb_s.json`) acts as the `memif` **master**.
- The **client-side** load balancer (`lb_c.json`) acts as the `memif` **slave**.
- The client and server applications are secondary processes that attach to their respective load balancers.

## Packet Flow
1.  The HTTP client application generates a request and sends it to the **client-side load balancer (LB_C)**.
2.  The **client-side load balancer (LB_C)** receives the packet and forwards it through the `memif` interface to the server-side load balancer.
3.  The **server-side load balancer (LB_S)** receives the packet from the `memif` interface.
4.  **LB_S** inspects the packet's destination IP and forwards it to the HTTP server.
5.  The HTTP server processes the request and sends the response back to **LB_S**.
6.  **LB_S** forwards the response through the `memif` interface back to **LB_C**.
7.  **LB_C** receives the response and forwards it back to the originating client.

## How to Run the Test

To run this performance test, follow these steps. The master process (`lb_s`) must be started before the slave process (`lb_c`).

**1. Start the Server-Side Load Balancer (Master):**

Launch the server-side (master) load balancer first. This will create the memif socket.

```bash
cd perf_tool/example/memif/test3
../../../../build/lb lb_s.json
```

**2. Start the Client-Side Load Balancer (Slave):**

In a separate terminal, launch the client-side (slave) load balancer.

```bash
cd perf_tool/example/memif/test3
../../../../build/lb lb_c.json
```

**3. Start the HTTP Server:**

In a separate terminal, start the HTTP server instance.

```bash
cd perf_tool/example/memif/test3
../../../../build/perf_tool server s.json
```

**4. Start the HTTP Client:**

In a separate terminal, start the HTTP client instance.

```bash
cd perf_tool/example/memif/test3
../../../../build/perf_tool client c.json
```