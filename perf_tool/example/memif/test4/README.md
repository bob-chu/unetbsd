# Performance Test Configuration (Direct Client-Server with Memif)

This document outlines the configuration for a performance test using a `memif` (shared memory) interface for direct communication between a single client and server. No load balancers are used in this setup.

## Network Diagram

The following diagram illustrates the simplified network topology.

```
+---------------------------------------------------------------------------------+
|                                  Host Machine                                   |
|                                                                                 |
|   +---------------------------+                           +---------------------------+
|   |        HTTP Client        |                           |        HTTP Server        |
|   |        (c.json)           |                           |        (s.json)           |
|   |                           |         +-------+         |                           |
|   |  DPDK Primary Process     |<--------| memif |-------->|  DPDK Primary Process     |
|   |  Core 2 (Server)          |         | link  |         |  Core 3 (Client)          |
|   |  Interface: memif0        |         +-------+         |  Interface: memif0        |
|   |                           |                           |                           |
|   +---------------------------+                           +---------------------------+
|                                                                                 |
+---------------------------------------------------------------------------------+
```

## Components

### HTTP Client (c.json)
- **`c.json`**: Configures the HTTP client instance, running on `Core 2`.
- It acts as a **DPDK primary process** and creates the `memif` interface as the **server**.

### HTTP Server (s.json)
- **`s.json`**: Configures the HTTP server instance, running on `Core 3`.
- It acts as a **DPDK primary process** and connects to the `memif` interface as the **client**.

## Network Topology
The test utilizes a **memif (shared memory)** interface for direct, high-speed communication between the client and server processes.
- The **HTTP Client (`c.json`)** acts as the `memif` **server**.
- The **HTTP Server (`s.json`)** acts as the `memif` **client**.

There are no load balancers in this configuration.

## Packet Flow
1.  The HTTP client application generates a request and sends it directly through the `memif` interface.
2.  The HTTP server receives the packet from the `memif` interface.
3.  The HTTP server processes the request and sends the response back through the `memif` interface.
4.  The HTTP client receives the response.

## How to Run the Test

To run this performance test, follow these steps. The memif server process (`c.json`) must be started before the memif client process (`s.json`).

**1. Start the HTTP Client (memif Server):**

Launch the HTTP client first. This will create the memif socket.

```bash
cd perf_tool/example/memif/test4
../../../../build/perf_tool client c.json
```

**2. Start the HTTP Server (memif Client):**

In a separate terminal, launch the HTTP server.

```bash
cd perf_tool/example/memif/test4
../../../../build/perf_tool server s.json
```