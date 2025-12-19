# Performance Test Configuration (1 Client, 1 Server)

This document outlines the configuration for a performance test designed to measure the throughput of HTTP requests between a single client and server in a DPDK-based environment.

The setup consists of one HTTP client, one HTTP server, and two load balancers. The entire test runs over a virtual Ethernet (veth) pair, simulating a direct network link between the client and server sides.

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
|   |  +----------v----------+  |         | veth  |         |  +----------v----------+  |
|   |  | Load Balancer (LB_C)|<----------| Pair  |---------->| Load Balancer (LB_S)|  |
|   |  |   (lb_c.json)       |  |         |       |         |  |   (lb_s.json)       |  |
|   |  | Core 4              |  |         |       |         |  | Core 5              |  |
|   |  | Interface: veth1    |  |         |       |         |  | Interface: veth0    |  |
|   |  +---------------------+  |         +-------+         |  +---------------------+  |
|   |                           |                           |                           |
|   +---------------------------+                           +---------------------------+
|                                                                                 |
+---------------------------------------------------------------------------------+
```

## Components

### Load Balancers (lb_c.json, lb_s.json)
- **`lb_c.json`**: The client-side load balancer. It runs on `Core 4` and attaches to the `veth1` interface. It is responsible for routing packets from/to the HTTP client based on its source IP address.
- **`lb_s.json`**: The server-side load balancer. It runs on `Core 5` and attaches to the `veth0` interface. It forwards incoming packets to the HTTP server and receives responses from it based on the destination IP address.

### HTTP Client (c.json)
- **`c.json`**: Configures the HTTP client instance, running on `Core 2`. It uses the source IP address range `192.168.1.10` - `192.168.1.17`. The client sends requests to and receives responses from the client-side load balancer (`lb_c`).

### HTTP Server (s.json)
- **`s.json`**: Configures the HTTP server instance, running on `Core 3`. It serves the destination IP address range `192.168.1.100` - `192.168.1.107`. The server listens for requests from and sends responses to the server-side load balancer (`lb_s`).

## Network Topology
The test utilizes a **veth (virtual Ethernet) pair** consisting of `veth0` and `veth1`. This pair acts like a virtual network cable, directly connecting the client-side components to the server-side components.
- The **client-side** components (LB_C, Client 1) are attached to the `veth1` interface.
- The **server-side** components (LB_S, Server 1) are attached to the `veth0` interface.

## Packet Flow
1.  The HTTP client application generates a request and sends it to the **client-side load balancer (LB_C)**.
2.  The **client-side load balancer (LB_C)**, attached to the `veth1` interface, receives the packet from the client. LB_C inspects the packet's source IP and forwards it through the veth pair to `veth0`.
3.  The **server-side load balancer (LB_S)**, listening on `veth0`, receives the packet from `veth1`.
4.  **LB_S** inspects the packet's destination IP and forwards it to the HTTP server.
5.  The HTTP server processes the request and sends the response back to **LB_S**.
6.  **LB_S** forwards the response through the veth pair to **LB_C**.
7.  **LB_C** receives the response and forwards it back to the originating client.

## How to Run the Test

To run this performance test, follow these steps. It's crucial to start the components in the specified order to ensure proper initialization and communication.

**1. Start the Load Balancers (in separate terminals):**

First, launch the client-side and server-side load balancers. These should typically be started first as they manage the network interfaces and packet forwarding.

```bash
cd perf_tool/example/veth_pair/test2
../../../../build/lb lb_s.json
../../../../build/lb lb_c.json
```

**2. Start the HTTP Server (in a separate terminal):**

Next, start the HTTP server instance. It will register with its DPDK ring and be ready to receive requests forwarded by `lb_s`.

```bash
cd perf_tool/example/veth_pair/test2
../../../../build/perf_tool server s.json
```

**3. Start the HTTP Client (in a separate terminal):**

Finally, start the HTTP client instance. It will connect to its DPDPK ring and begin generating traffic, which will be handled by `lb_c`.

```bash
cd perf_tool/example/veth_pair/test2
../../../../build/perf_tool client c.json
```
