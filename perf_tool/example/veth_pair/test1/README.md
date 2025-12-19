# Performance Test Configuration

This document outlines the configuration for a performance test designed to measure the throughput of HTTP requests between clients and servers in a DPDK-based environment.

The setup consists of two HTTP clients, two HTTP servers, and two load balancers. The entire test runs over a virtual Ethernet (veth) pair, simulating a direct network link between the client and server sides.

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
|   |  | Core 2              |  |         |       |         |  | Core 4              |  |
|   |  | IPs: 192.168.1.10-17|  |         |       |         |  | IPs: 192.168.1.100-107|  |
|   |  +----------^----------+  |         |       |         |  +----------^----------+  |
|   |             | (to/from)  |         |       |         |             | (to/from) |
|   |  +----------v----------+  |         | veth  |         |  +----------v----------+  |
|   |  | Load Balancer (LB_C)|<----------| Pair  |---------->| Load Balancer (LB_S)|  |
|   |  |   (lb_c.json)       |  |         |       |         |  |   (lb_s.json)       |  |
|   |  | Core 6              |  |         |       |         |  | Core 7              |  |
|   |  | Interface: veth1    |  |         |       |         |  | Interface: veth0    |  |
|   |  +----------^----------+  |         |       |         |  +----------^----------+  |
|   |             | (to/from)  |         |       |         |             | (to/from) |
|   |  +----------v----------+  |         +-------+         |  +----------v----------+  |
|   |  |   HTTP Client 2     |  |                           |  |   HTTP Server 2     |  |
|   |  |   (c1.json)         |  |                           |  |   (s1.json)         |  |
|   |  | Core 3              |  |                           |  | Core 5              |  |
|   |  | IPs: 192.168.1.18-24|  |                           |  | IPs: 192.168.1.108-115|  |
|   |  +---------------------+  |                           |  +---------------------+  |
|   |                           |                           |                           |
|   +---------------------------+                           +---------------------------+
|                                                                                 |
+---------------------------------------------------------------------------------+
```

## Components

### Load Balancers (lb_c.json, lb_s.json)
- **`lb_c.json`**: The client-side load balancer. It runs on `Core 6` and attaches to the `veth1` interface. It is responsible for routing packets from/to the two HTTP clients based on their source IP addresses.
- **`lb_s.json`**: The server-side load balancer. It runs on `Core 7` and attaches to the `veth0` interface. It forwards incoming packets to the appropriate HTTP server and receives responses from them based on the destination IP address.

### HTTP Clients (c.json, c1.json)
- **`c.json`**: Configures the first HTTP client instance, running on `Core 2`. It uses the source IP address range `192.168.1.10` - `192.168.1.17`.
- **`c1.json`**: Configures the second HTTP client instance, running on `Core 3`. It uses the source IP address range `192.168.1.18` - `192.168.1.24`.

Both clients send requests to and receive responses from the client-side load balancer (`lb_c`).

### HTTP Servers (s.json, s1.json)
- **`s.json`**: Configures the first HTTP server instance, running on `Core 4`. It serves the destination IP address range `192.168.1.100` - `192.168.1.107`.
- **`s1.json`**: Configures the second HTTP server instance, running on `Core 5`. It serves the destination IP address range `192.168.1.108` - `192.168.1.115`.

Both servers listen for requests from and send responses to the server-side load balancer (`lb_s`).

## Network Topology
The test utilizes a **veth (virtual Ethernet) pair** consisting of `veth0` and `veth1`. This pair acts like a virtual network cable, directly connecting the client-side components to the server-side components.
- The **client-side** components (LB_C, Client 1, Client 2) are attached to the `veth1` interface.
- The **server-side** components (LB_S, Server 1, Server 2) are attached to the `veth0` interface.

## Packet Flow
1.  An HTTP client application generates a request and sends it to the **client-side load balancer (LB_C)**.
2.  The **client-side load balancer (LB_C)**, attached to the `veth1` interface, receives the packet from the client. LB_C inspects the packet's source IP and forwards it through the veth pair to `veth0`.
3.  The **server-side load balancer (LB_S)**, listening on `veth0`, receives the packet from `veth1`.
4.  **LB_S** inspects the packet's destination IP and forwards it to the corresponding HTTP server (Server 1 or Server 2).
5.  The HTTP server processes the request and sends the response back to **LB_S**.
6.  **LB_S** forwards the response through the veth pair to **LB_C**.
7.  **LB_C** receives the response and forwards it back to the originating client.

## How to Run the Test

To run this performance test, follow these steps. It's crucial to start the components in the specified order to ensure proper initialization and communication.

**1. Start the Load Balancers (in separate terminals):**

First, launch the client-side and server-side load balancers. These should typically be started first as they manage the network interfaces and packet forwarding.

```bash
./build/lb lb_s.json
./build/lb lb_c.json
```

**2. Start the HTTP Servers (in separate terminals):**

Next, start both HTTP server instances. They will register with their respective DPDK rings and be ready to receive requests forwarded by `lb_s`.

```bash
./build/perf_tool server s.json
./build/perf_tool server s1.json
```

**3. Start the HTTP Clients (in separate terminals):**

Finally, start the HTTP client instances. They will connect to their respective DPDK rings and begin generating traffic, which will be handled by `lb_c`.

```bash
./build/perf_tool client c.json
./build/perf_tool client c1.json
```
