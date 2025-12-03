# HTTPS Implementation Plan for perf_tool

This document outlines the remaining tasks for implementing HTTPS support in the `perf_tool`.

## 1. Architecture Overview

The architecture introduces a dedicated SSL layer between the HTTP layer and the TCP layer.

```
+-----------------+
|   HTTP Layer    | (http_client.c, http_server.c)
+-----------------+
      ^     | (Callbacks: upcall/downcall)
      |     v
+-----------------+
|    SSL Layer    | (ssl_layer.c)
+-----------------+
      ^     |
      |     v
+-----------------+
|    TCP Layer    | (Userspace TCP Stack - UNCHANGED)
+-----------------+
```

## 2. Implementation Plan

The core of this implementation revolves around integrating an asynchronous SSL/TLS layer that operates directly on I/O buffers rather than traditional socket file descriptors. This is crucial for compatibility with the existing user-space TCP stack and its asynchronous event-driven model.

### 2.1. SSL Layer (`ssl_layer.c`)

*   **Asynchronous Handshake:** Implement non-blocking SSL handshake routines. This will involve:
    *   Initializing the SSL context and connection in a non-blocking manner.
    *   Handling `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE` during `SSL_accept` and `SSL_connect` by registering appropriate read/write events with the underlying event loop.
    *   Managing the handshake state machine to progress through the different phases (e.g., client hello, server hello, certificate exchange, key exchange) without blocking the main thread.
*   **Buffer-based I/O:**
    *   Modify `ssl_layer.c` to use `SSL_read` and `SSL_write` with application-provided input/output buffers. The `ssl_layer` will manage the OpenSSL internal BIO (Basic I/O) buffers.
    *   The `ssl_layer` will receive raw encrypted bytes from the TCP layer into an input buffer, pass them to OpenSSL for decryption using `SSL_read`, and then provide the decrypted data to the HTTP layer.
    *   Conversely, it will take cleartext data from the HTTP layer, encrypt it using `SSL_write`, and pass the resulting encrypted bytes to the TCP layer via an output buffer.
    *   Event-driven I/O will be managed by pushing/pulling data to/from the TCP layer as `SSL_ERROR_WANT_READ`/`SSL_ERROR_WANT_WRITE` conditions dictate.
*   **Error Handling:** Implement robust error handling for SSL operations, including `SSL_get_error` to interpret return codes and manage various SSL states.

### 2.2. HTTP Layer Integration (`http_client.c`, `http_server.c`)

*   **Client (`http_client.c`):**
    *   Adapt the client to initiate an SSL handshake upon connection for HTTPS requests.
    *   Integrate with the `ssl_layer` to send and receive application data securely.
    *   Handle asynchronous events from the `ssl_layer` to manage data flow.
*   **Server (`http_server.c`):**
    *   Adapt the server to perform an SSL handshake upon receiving a new connection for HTTPS.
    *   Integrate with the `ssl_layer` for secure data exchange with clients.
    *   Process asynchronous notifications from the `ssl_layer` to handle incoming encrypted data and outgoing cleartext data.
    
    ### 2.3. Detailed Task Breakdown
    
    #### 2.3.1. SSL Layer (`ssl_layer.c`) Implementation Tasks
    
    *   Initialize the SSL context and connection in a non-blocking manner.
        *   **Unit Test Plan:**
            *   **Purpose:** Verify correct non-blocking initialization of SSL_CTX and SSL objects.
            *   **Subtasks:**
                *   Test `ssl_init_ctx` for proper context creation.
                *   Test `ssl_new_connection` for correct SSL object allocation and non-blocking setup.
                *   Verify error handling during initialization (e.g., memory allocation failure).
                *   Ensure `SSL_CTX_free` and `SSL_free` clean up resources correctly.
    
    *   Handle `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE` during `SSL_accept` and `SSL_connect` by registering appropriate read/write events.
        *   **Unit Test Plan:**
            *   **Purpose:** Confirm that the SSL layer correctly identifies and signals `WANT_READ`/`WANT_WRITE` states for event loop integration.
            *   **Subtasks:**
                *   Simulate `SSL_accept` and `SSL_connect` returning `WANT_READ` and verify the SSL layer signals a read event.
                *   Simulate `SSL_accept` and `SSL_connect` returning `WANT_WRITE` and verify the SSL layer signals a write event.
                *   Test transitions between `WANT_READ`, `WANT_WRITE`, and successful completion during handshake.
    
    *   Manage the handshake state machine to progress through phases (client hello, server hello, etc.) without blocking.
        *   **Unit Test Plan:**
            *   **Purpose:** Validate the state machine's ability to drive the handshake to completion asynchronously.
            *   **Subtasks:**
                *   Test a full asynchronous client handshake (`SSL_connect`).
                *   Test a full asynchronous server handshake (`SSL_accept`).
                *   Verify that intermediate handshake steps are handled without blocking.
                *   Test scenarios with fragmented handshake messages.
    
    *   Modify `ssl_layer.c` to use `SSL_read` and `SSL_write` with application-provided input/output buffers.
        *   **Unit Test Plan:**
            *   **Purpose:** Ensure `SSL_read`/`SSL_write` correctly process data from/to application buffers.
            *   **Subtasks:**
                *   Test `SSL_read` with various sizes of encrypted input data and verify correct decryption into output buffer.
                *   Test `SSL_write` with various sizes of cleartext input data and verify correct encryption into output buffer.
                *   Verify `WANT_READ`/`WANT_WRITE` handling during data transfer operations.
    
    *   Manage OpenSSL internal BIO (Basic I/O) buffers within `ssl_layer.c`.
        *   **Unit Test Plan:**
            *   **Purpose:** Confirm proper management and interaction with OpenSSL's internal BIO.
            *   **Subtasks:**
                *   Verify that data written to the BIO by `SSL_write` can be read out correctly from the BIO.
                *   Verify that data written into the BIO can be read by `SSL_read`.
                *   Test BIO buffer resizing and memory management.
    
    *   Implement logic in `ssl_layer.c` to receive raw encrypted bytes from the TCP layer into an input buffer for decryption via `SSL_read`.
        *   **Unit Test Plan:**
            *   **Purpose:** Validate the interface between the TCP layer's input and `SSL_read` via intermediate buffer.
            *   **Subtasks:**
                *   Simulate receiving encrypted data from TCP into an input buffer and passing it to the SSL layer for decryption.
                *   Verify `SSL_read` consumes the correct amount of encrypted data and produces cleartext.
                *   Test scenarios with incomplete encrypted frames.
    
    *   Implement logic in `ssl_layer.c` to provide decrypted data to the HTTP layer.
        *   **Unit Test Plan:**
            *   **Purpose:** Ensure decrypted data is correctly made available to the HTTP layer.
            *   **Subtasks:**
                *   Verify that after successful `SSL_read`, the cleartext data is accessible to a simulated HTTP layer callback or buffer.
                *   Test varying sizes of decrypted data delivery.
    
    *   Implement logic in `ssl_layer.c` to take cleartext data from the HTTP layer, encrypt via `SSL_write`, and pass encrypted bytes to the TCP layer via an output buffer.
        *   **Unit Test Plan:**
            *   **Purpose:** Validate the interface between the HTTP layer's output and `SSL_write` via intermediate buffer for encryption.
            *   **Subtasks:**
                *   Simulate HTTP layer providing cleartext data, and verify `SSL_write` encrypts it and places it into an output buffer.
                *   Verify the encrypted data in the output buffer is ready for the TCP layer.
                *   Test scenarios where `SSL_write` produces fragmented encrypted frames.
    
    *   Manage event-driven I/O in `ssl_layer.c` by pushing/pulling data to/from the TCP layer based on `SSL_ERROR_WANT_READ`/`SSL_ERROR_WANT_WRITE` conditions.
        *   **Unit Test Plan:**
            *   **Purpose:** Confirm that the SSL layer correctly interacts with the underlying event loop for data exchange with the TCP layer.
            *   **Subtasks:**
                *   Verify that when `SSL_read` returns `WANT_READ`, the SSL layer requests data from the TCP layer.
                *   Verify that when `SSL_write` returns `WANT_WRITE`, the SSL layer signals that it can accept more data to send to the TCP layer.
                *   Test continuous data flow driven by these events.
    
    *   Implement robust error handling for SSL operations, including `SSL_get_error` in `ssl_layer.c`.
        *   **Unit Test Plan:**
            *   **Purpose:** Ensure all OpenSSL errors are caught, interpreted, and handled gracefully.
            *   **Subtasks:**
                *   Inject various OpenSSL error conditions (e.g., invalid certificate, handshake failure, data corruption) and verify `SSL_get_error` is used correctly.
                *   Test that appropriate error codes or states are propagated to higher layers.
                *   Verify resource cleanup during error conditions.    
    #### 2.3.2. HTTP Layer Integration Tasks
    
    **Client (`http_client.c`)**
    
    *   Adapt client to initiate an SSL handshake upon connection for HTTPS requests.
        *   **Unit Test Plan:**
            *   **Purpose:** Verify that the client correctly initiates the SSL handshake for HTTPS connections.
            *   **Subtasks:**
                *   Test client connection to an HTTPS server and confirm SSL handshake initiation via `ssl_layer`.
                *   Verify client correctly handles initial handshake states (e.g., waiting for server hello).
    
    *   Integrate with the `ssl_layer` to send and receive application data securely.
        *   **Unit Test Plan:**
            *   **Purpose:** Ensure the client can send cleartext HTTP requests and receive cleartext HTTP responses securely through the `ssl_layer`.
            *   **Subtasks:**
                *   Send various HTTP requests (GET, POST) through the `ssl_layer` and verify data integrity on the server side.
                *   Receive various HTTP responses through the `ssl_layer` and verify data integrity on the client side.
    
    *   Handle asynchronous events from the `ssl_layer` to manage data flow.
        *   **Unit Test Plan:**
            *   **Purpose:** Confirm client's ability to react to `WANT_READ`/`WANT_WRITE` events from `ssl_layer` for efficient data handling.
            *   **Subtasks:**
                *   Simulate `ssl_layer` returning `WANT_READ` and verify client attempts to read more data.
                *   Simulate `ssl_layer` returning `WANT_WRITE` and verify client attempts to write more data.
                *   Test continuous data exchange under asynchronous conditions.
    
    **Server (`http_server.c`)**
    
    *   Adapt server to perform an SSL handshake upon receiving a new connection for HTTPS.
        *   **Unit Test Plan:**
            *   **Purpose:** Verify server correctly performs the SSL handshake for incoming HTTPS connections.
            *   **Subtasks:**
                *   Test server accepting an HTTPS connection and performing `SSL_accept` via `ssl_layer`.
                *   Verify server correctly handles initial handshake states (e.g., sending server hello).
    
    *   Integrate with the `ssl_layer` for secure data exchange with clients.
        *   **Unit Test Plan:**
            *   **Purpose:** Ensure the server can receive cleartext HTTP requests and send cleartext HTTP responses securely through the `ssl_layer`.
            *   **Subtasks:**
                *   Receive various HTTP requests (GET, POST) through the `ssl_layer` and verify data integrity.
                *   Send various HTTP responses through the `ssl_layer` and verify data integrity on the client side.
    
    *   Process asynchronous notifications from the `ssl_layer` to handle incoming encrypted data and outgoing cleartext data.
        *   **Unit Test Plan:**
            *   **Purpose:** Confirm server's ability to react to `WANT_READ`/`WANT_WRITE` events from `ssl_layer` for efficient data handling.
            *   **Subtasks:**
                *   Simulate `ssl_layer` returning `WANT_READ` and verify server attempts to read more data.
                *   Simulate `ssl_layer` returning `WANT_WRITE` and verify server attempts to write more data.
                *   Test continuous data exchange under asynchronous conditions.## 3. Test Plan

This test plan focuses on validating the asynchronous, buffer-based SSL implementation and its integration with the existing user-space TCP stack. All tests will be executed within the `my-ubuntu` Docker container.

### 3.1. Unit Testing (ssl_layer.c) - **Pending**

*   **SSL Context & Session Management:**
    *   Verify correct initialization and destruction of SSL_CTX and SSL objects.
    *   Test session renegotiation and reuse.
*   **Asynchronous Handshake:**
    *   Simulate non-blocking `SSL_accept` and `SSL_connect` scenarios.
    *   Verify that `SSL_ERROR_WANT_READ` and `SSL_ERROR_WANT_WRITE` are correctly handled and trigger appropriate event registrations.
    *   Ensure the handshake completes successfully without blocking.
*   **Buffer I/O Operations:**
    *   Test `SSL_read` and `SSL_write` with various buffer sizes and data patterns.
    *   Verify data encryption and decryption fidelity.
    *   Test edge cases like partial reads/writes and empty buffers.
*   **Error Handling:**
    *   Inject errors (e.g., corrupted data, handshake failures) and verify that the `ssl_layer` gracefully handles them and reports appropriate error codes.

### 3.2. End-to-End Testing - **Pending**

*   **HTTPS Connection Establishment:**
    *   Configure the `perf_tool` server with a self-signed certificate.
    *   Run the `perf_tool` client against the server, both within the `my-ubuntu` Docker container.
    *   Verify successful HTTPS connection establishment and a complete request/response cycle for a simple HTTP GET/POST.
*   **Asynchronous Data Transfer:**
    *   Test large data transfers over HTTPS to confirm proper handling of asynchronous buffer operations.
    *   Verify data integrity (no corruption) during high-volume transfers.
*   **Concurrent Connections:**
    *   Simulate multiple concurrent HTTPS clients to stress-test the asynchronous SSL handshake and data processing.
    *   Monitor resource utilization (CPU, memory) to identify potential bottlenecks.
*   **Performance Metrics:**
    *   **HTTPS CPS & Bandwidth:**
        *   Measure Connections Per Second (CPS) and Bandwidth (BW) for HTTPS connections.
        *   Compare these metrics against the baseline plaintext HTTP performance to quantify the overhead introduced by SSL/TLS.
    *   **HTTP Regression:**
        *   Ensure existing HTTP CPS and BW measurements are not adversely affected by the HTTPS implementation.
*   **Error Scenarios:**
    *   Test client/server disconnections during handshake and data transfer.
    *   Verify proper error reporting and connection teardown.

### 3.3. Post-Implementation Goals - **In Progress**

*   The `perf_tool` must accurately measure HTTPS Connections Per Second (CPS) and Bandwidth (BW).
*   HTTPS integration should not impact existing HTTP performance measurement capabilities.
*   **Note:** Updated `http_server.c` and `http_client.c` to track CPS and bandwidth for HTTPS connections. Further testing in the `my-ubuntu` Docker container is needed to confirm CPS and BW metrics for HTTPS.

## 3. Development Environment and Build System

*   All development, building, and testing must be performed within the `my-ubuntu` Docker container.
*   The build system used for this project is Meson.
