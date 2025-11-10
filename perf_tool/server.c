#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>

#include <ev.h>
#include <u_socket.h>

#include "server.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"
#include "deps/picohttpparser/picohttpparser.h"

extern struct ev_loop *g_main_loop;

// Forward declarations for event callbacks
static void server_listen_read_cb(void *handle, int events);
static void client_conn_read_cb(void *handle, int events);
static void client_conn_write_cb(void *handle, int events);
static void client_conn_close_cb(void *handle, int events);

// Preallocated response buffers for different paths
static char *response_buffer_hello = NULL;
static char *response_buffer_another = NULL;
static char *response_buffer_default = NULL;
static size_t response_size_hello = 0;
static size_t response_size_another = 0;
static size_t response_size_default = 0;

#define BUFFER_SIZE 7000 
// Structure to hold client-specific data
typedef struct client_data {
    struct netbsd_handle nh;
    perf_config_t *config;
    char *recv_buffer;
    size_t recv_buffer_size;
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len;
    int cleaning_up; // New flag
    char *response_buffer;      // Pointer to the response buffer to send
    size_t response_size;       // Total size of response to send
    size_t response_sent;       // Bytes already sent
    char response_header[BUFFER_SIZE];  // Buffer for response header
    size_t header_size;         // Size of the header
    int header_sent;            // Flag to indicate if header is sent
    int in_use;                 // Flag to indicate if this entry is in use
    TAILQ_ENTRY(client_data) free_list_entry; // Linked list entry for free list management
} client_data_t;

// Pre-allocated array and queue management for client_data_t
#define CLIENT_DATA_POOL_SIZE 16384
static client_data_t client_data_pool[CLIENT_DATA_POOL_SIZE];

// Use TAILQ for managing free list of client_data
TAILQ_HEAD(client_data_free_list, client_data);
static struct client_data_free_list free_client_data_list = TAILQ_HEAD_INITIALIZER(free_client_data_list);
static int client_data_count = 0; // Number of entries in use

typedef struct {
    struct netbsd_handle listen_nh;
    perf_config_t *config;
} listen_watcher_data_t;

static void server_conn_cleanup(client_data_t *client_data);

void init_response_buffers(perf_config_t *config) {
    // Seed random number generator
    srand(time(NULL));
    
    // A simple list of words to create human-readable random text
    const char *words[] = {
        "hello", "world", "random", "text", "human", "readable", "response", "server", "data", "content",
        "network", "performance", "test", "tool", "connection", "protocol", "internet", "message", "information", "system"
    };
    const int word_count = sizeof(words) / sizeof(words[0]);
    
    // Allocate and fill response buffers with human-readable random text and signatures
    response_size_hello = config->http_config.response_size_hello;
    if (response_size_hello > 0) {
        response_buffer_hello = malloc(response_size_hello);
        if (response_buffer_hello) {
            size_t pos = 0;
            while (pos < response_size_hello) {
                int word_index = rand() % word_count;
                size_t word_len = strlen(words[word_index]);
                if (pos + word_len + 1 <= response_size_hello) {
                    memcpy(response_buffer_hello + pos, words[word_index], word_len);
                    pos += word_len;
                    response_buffer_hello[pos++] = ' ';
                } else {
                    break;
                }
            }
            LOG_INFO("Allocated response buffer for /hello: %zu bytes", response_size_hello);
        }
    }
    
    response_size_another = config->http_config.response_size_another;
    if (response_size_another > 0) {
        response_buffer_another = malloc(response_size_another);
        if (response_buffer_another) {
            size_t pos = 0;
            while (pos < response_size_another) {
                int word_index = rand() % word_count;
                size_t word_len = strlen(words[word_index]);
                if (pos + word_len + 1 <= response_size_another) {
                    memcpy(response_buffer_another + pos, words[word_index], word_len);
                    pos += word_len;
                    response_buffer_another[pos++] = ' ';
                } else {
                    break;
                }
            }
            LOG_INFO("Allocated response buffer for /another: %zu bytes", response_size_another);
        }
    }
    
    response_size_default = config->http_config.response_size_default;
    if (response_size_default > 0) {
        response_buffer_default = malloc(response_size_default);
        if (response_buffer_default) {
            size_t pos = 0;
            while (pos < response_size_default) {
                int word_index = rand() % word_count;
                size_t word_len = strlen(words[word_index]);
                if (pos + word_len + 1 <= response_size_default) {
                    memcpy(response_buffer_default + pos, words[word_index], word_len);
                    pos += word_len;
                    response_buffer_default[pos++] = ' ';
                } else {
                    break;
                }
            }
            LOG_INFO("Allocated response buffer for default: %zu bytes", response_size_default);
        }
    }
}

void free_response_buffers(void) {
    if (response_buffer_hello) {
        free(response_buffer_hello);
        response_buffer_hello = NULL;
    }
    if (response_buffer_another) {
        free(response_buffer_another);
        response_buffer_another = NULL;
    }
    if (response_buffer_default) {
        free(response_buffer_default);
        response_buffer_default = NULL;
    }
    LOG_INFO("Freed response buffers");
    
    // Free client data pool buffers
    for (int i = 0; i < CLIENT_DATA_POOL_SIZE; i++) {
        if (client_data_pool[i].recv_buffer) {
            free(client_data_pool[i].recv_buffer);
            client_data_pool[i].recv_buffer = NULL;
        }
    }
    LOG_INFO("Freed client data pool buffers");
}

static void init_client_data_pool(perf_config_t *config) {
    TAILQ_INIT(&free_client_data_list);
    for (int i = 0; i < CLIENT_DATA_POOL_SIZE; i++) {
        client_data_t *client_data = &client_data_pool[i];
        memset(client_data, 0, sizeof(client_data_t));
        client_data->recv_buffer_size = (strcmp(config->objective.type, "HTTP_REQUESTS") == 0 || config->client_payload.size < BUFFER_SIZE) ? BUFFER_SIZE : config->client_payload.size;
        client_data->recv_buffer = (char *)malloc(client_data->recv_buffer_size);
        if (!client_data->recv_buffer) {
            LOG_ERROR("Failed to allocate memory for client receive buffer at index %d.", i);
            exit(1);
        }
        client_data->config = config;
        client_data->in_use = 0;
        TAILQ_INSERT_TAIL(&free_client_data_list, client_data, free_list_entry);
    }
    client_data_count = 0;
    LOG_INFO("Initialized client data pool with %d entries", CLIENT_DATA_POOL_SIZE);
}

static client_data_t *get_client_data_from_pool() {
    if (client_data_count >= CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("No free client data entries available in pool.");
        return NULL;
    }
    client_data_t *client_data = TAILQ_FIRST(&free_client_data_list);
    if (client_data == NULL) {
        LOG_ERROR("No free client data available despite count check!");
        return NULL;
    }
    if (client_data->in_use) {
        LOG_ERROR("Client data from free list is already in use!");
        return NULL;
    }
    TAILQ_REMOVE(&free_client_data_list, client_data, free_list_entry);
    client_data->in_use = 1;
    client_data_count++;
    int index = client_data - client_data_pool;
    LOG_DEBUG("Allocated client data from pool, index=%d, count=%d", index, client_data_count);
    return client_data;
}

static void return_client_data_to_pool(client_data_t *client_data) {
    if (!client_data->in_use) {
        LOG_ERROR("Returning client data that is not in use!");
        return;
    }
    int index = client_data - client_data_pool;
    if (index < 0 || index >= CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("Invalid client data index %d outside pool range!", index);
        return;
    }
    memset(&client_data->nh, 0, sizeof(struct netbsd_handle));
    client_data->cleaning_up = 0;
    client_data->response_buffer = NULL;
    client_data->response_size = 0;
    client_data->response_sent = 0;
    client_data->header_size = 0;
    client_data->header_sent = 0;
    client_data->in_use = 0;
    TAILQ_INSERT_TAIL(&free_client_data_list, client_data, free_list_entry);
    client_data_count--;
    LOG_DEBUG("Returned client data to pool, index=%d, count=%d", index, client_data_count);
}

void run_server(struct ev_loop *loop, perf_config_t *config) {
    LOG_INFO("Starting server setup...");

    scheduler_init(loop, config);
    
    // Initialize response buffers
    init_response_buffers(config);
    
    // Initialize client data pool
    init_client_data_pool(config);

    // Calculate the number of ports in the range
    int port_count = config->network.dst_port_end - config->network.dst_port_start + 1;
    listen_watcher_data_t *listen_data_array = (listen_watcher_data_t *)malloc(sizeof(listen_watcher_data_t) * port_count);
    if (!listen_data_array) {
        LOG_ERROR("Failed to allocate memory for listen data array.");
        return;
    }
    memset(listen_data_array, 0, sizeof(listen_watcher_data_t) * port_count);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    enum proto_type proto = (strcmp(config->network.protocol, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
    int type = (proto == PROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

    for (int i = 0; i < port_count; i++) {
        int port = config->network.dst_port_start + i;
        listen_watcher_data_t *listen_data = &listen_data_array[i];
        listen_data->config = config;
        listen_data->listen_nh.proto = proto;
        listen_data->listen_nh.type = type;
        listen_data->listen_nh.is_ipv4 = 1; // Assuming IPv4 for now

        if (netbsd_socket(&listen_data->listen_nh) != 0) {
            LOG_ERROR("Failed to create listen socket for port %d: %s", port, strerror(errno));
            // Clean up previously created sockets
            for (int j = 0; j < i; j++) {
                netbsd_close(&listen_data_array[j].listen_nh);
            }
            free(listen_data_array);
            return;
        }
        LOG_DEBUG("listen socket for port %d: nh: %p, so: %p\n", port, &listen_data->listen_nh, listen_data->listen_nh.so);

        server_addr.sin_port = htons(port);
        if (netbsd_bind(&listen_data->listen_nh, (struct sockaddr *)&server_addr) != 0) {
            LOG_ERROR("Failed to bind listen socket to %s:%d: %s", config->network.dst_ip_start, port, strerror(errno));
            netbsd_close(&listen_data->listen_nh);
            // Clean up previously created sockets
            for (int j = 0; j < i; j++) {
                netbsd_close(&listen_data_array[j].listen_nh);
            }
            free(listen_data_array);
            return;
        }

        if (proto == PROTO_TCP) {
            if (netbsd_listen(&listen_data->listen_nh, 128) != 0) {
                LOG_ERROR("Failed to listen on socket for port %d: %s", port, strerror(errno));
                netbsd_close(&listen_data->listen_nh);
                // Clean up previously created sockets
                for (int j = 0; j < i; j++) {
                    netbsd_close(&listen_data_array[j].listen_nh);
                }
                free(listen_data_array);
                return;
            }
            LOG_INFO("Server listening on %s:%d (TCP)", config->network.dst_ip_start, port);
            listen_data->listen_nh.read_cb = server_listen_read_cb;
            listen_data->listen_nh.data = listen_data;
            netbsd_io_start(&listen_data->listen_nh);
        } else { // UDP
            LOG_INFO("Server listening on %s:%d (UDP)", config->network.dst_ip_start, port);
            // For UDP, the listen socket is also the data socket.
            client_data_t *udp_client_data = get_client_data_from_pool();
            if (!udp_client_data) {
                LOG_ERROR("Failed to get UDP client data from pool on port %d.", port);
                netbsd_close(&listen_data->listen_nh);
                // Clean up previously created sockets
                for (int j = 0; j < i; j++) {
                    netbsd_close(&listen_data_array[j].listen_nh);
                }
                free(listen_data_array);
                return;
            }
            memcpy(&udp_client_data->nh, &listen_data->listen_nh, sizeof(struct netbsd_handle));
            udp_client_data->nh.data = udp_client_data; // Self-reference for callbacks
            udp_client_data->nh.read_cb = client_conn_read_cb;
            netbsd_io_start(&udp_client_data->nh);
        }
    }
    LOG_INFO("Server setup complete for port range %d-%d", config->network.dst_port_start, config->network.dst_port_end);
}

static void server_listen_read_cb(void *handle, int events) {
    listen_watcher_data_t *listen_data = (listen_watcher_data_t *)((struct netbsd_handle *)handle)->data;
    struct netbsd_handle *listen_nh = &listen_data->listen_nh;
    int ret = 0;

    while (1) {
        client_data_t *client_data = get_client_data_from_pool();
        if (!client_data) {
            LOG_ERROR("Failed to get client data from pool.");
            break;
        }
        memset(client_data->recv_buffer, 0, client_data->recv_buffer_size);
        client_data->nh.data = client_data; // Self-reference for callbacks

        if ((ret = netbsd_accept(listen_nh, &client_data->nh)) != 0) {
            return_client_data_to_pool(client_data);
            /*
            if (ret != EWOULDBLOCK && ret != EAGAIN) {
                LOG_ERROR("Failed to accept new connection: %s", strerror(errno));
            }
            */
            break; // No more connections or an error occurred
        }

        LOG_INFO("Accepted new TCP connection. new_nh: %p, new_so: %p\n",
                &client_data->nh, client_data->nh.so);
        scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, 1);
        metrics_inc_success(); // Increment success count for successful connection

        client_data->nh.read_cb = client_conn_read_cb;
        client_data->nh.write_cb = client_conn_write_cb;
        client_data->nh.close_cb = client_conn_close_cb;
        netbsd_io_start(&client_data->nh);
    }
}

static void client_conn_read_cb(void *handle, int events)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    client_data_t *client_data = (client_data_t *)nh->data;

    // Assert that client_data is within the pool range
    if (client_data < client_data_pool || client_data >= client_data_pool + CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("Invalid client_data pointer outside pool range: %p", client_data);
        return;
    }
    if (!client_data->in_use) {
        LOG_ERROR("client_data not marked as in use: %p", client_data);
        return;
    }

    int socket_error = netbsd_socket_error(nh);
    if (nh->so == NULL || client_data->cleaning_up || nh->is_closing || socket_error != 0) {
        LOG_DEBUG("Read callback ignored: socket closed, closing, or in error state (error=%d)", socket_error);
        server_conn_cleanup(client_data);
        return; // Socket already closed, cleaning up, marked as closing, or in error state
    }

    struct iovec iov;
    iov.iov_base = client_data->recv_buffer;
    iov.iov_len = client_data->recv_buffer_size;

    ssize_t bytes_read = 0;
    if (nh->proto == PROTO_TCP) {
        bytes_read = netbsd_read(nh, &iov, 1);
    } else { // UDP
        struct sockaddr_in remote_addr;
        socklen_t remote_addr_len = sizeof(remote_addr);
        bytes_read = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&remote_addr);
        if (bytes_read > 0) {
            // Store remote_addr in client_data for sending response
            memcpy(&client_data->remote_addr, &remote_addr, sizeof(remote_addr));
            client_data->remote_addr_len = remote_addr_len;
        }
    }

    if (bytes_read > 0) {
        if (bytes_read > client_data->recv_buffer_size) {
            LOG_ERROR("Received more data than buffer can hold. Buffer size: %zu, received: %zd", client_data->recv_buffer_size, bytes_read);
            metrics_inc_failure();
            server_conn_cleanup(client_data);
            return;
        }
        LOG_INFO("Received %zd bytes.", bytes_read);
        scheduler_inc_stat(STAT_BYTES_RECEIVED, bytes_read);

        const char *method, *path;
        int pret, minor_version;
        struct phr_header headers[100];
        size_t method_len, path_len, num_headers;

        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_request(client_data->recv_buffer, bytes_read, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);

        LOG_INFO("phr parse ret: %d", pret);
        if (pret > 0) { // successful parse
            int status_code = 200;
            client_data->response_sent = 0;
            client_data->header_sent = 0;

            if (strncmp(path, "/hello", path_len) == 0 && response_buffer_hello) {
                client_data->response_buffer = response_buffer_hello;
                client_data->response_size = response_size_hello;
            } else if (strncmp(path, "/another", path_len) == 0 && response_buffer_another) {
                client_data->response_buffer = response_buffer_another;
                client_data->response_size = response_size_another;
            } else {
                client_data->response_buffer = response_buffer_default;
                client_data->response_size = response_size_default;
                status_code = 404;
            }

            // If no response buffer is set, use a small default message
            if (!client_data->response_buffer) {
                static char default_msg[] = "<html><body><h1>404 Not Found</h1></body></html>";
                client_data->response_buffer = default_msg;
                client_data->response_size = strlen(default_msg);
                status_code = 404;
            }

            // Set Content-Length as per the configuration, excluding signatures
            size_t content_length = 0;
            if (strncmp(path, "/hello", path_len) == 0) {
                content_length = client_data->config->http_config.response_size_hello;
            } else if (strncmp(path, "/another", path_len) == 0) {
                content_length = client_data->config->http_config.response_size_another;
            } else {
                content_length = client_data->config->http_config.response_size_default;
            }

            client_data->header_size = snprintf(client_data->response_header, sizeof(client_data->response_header),
                "HTTP/1.1 %d %s\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %zu\r\n"
                "\r\n",
                status_code, status_code == 200 ? "OK" : "Not Found", content_length);

            // Trigger the write callback to start sending the response
            client_conn_write_cb(handle, events);
            return;
        } else if (pret == -1) { // parse error
            LOG_ERROR("HTTP parse error");
            metrics_inc_failure();
            server_conn_cleanup(client_data);
        } else { // incomplete request
            LOG_DEBUG("Incomplete HTTP request");
            // For this tool, we assume full request in one read and close
            server_conn_cleanup(client_data);
        }
    } else if (bytes_read == 0) {
        LOG_INFO("Client closed connection.");
        server_conn_cleanup(client_data); // Call cleanup
    } else {
        if (bytes_read == -35 || bytes_read == -EWOULDBLOCK) {
            LOG_DEBUG("EAGAIN/EWOULDBLOCK during read, will retry.");
        } else {
            if (bytes_read != -32 &&  bytes_read != -54) {
                LOG_ERROR("Failed to read from socket: nh:%p, so: %p, (errno: %d)", nh, nh->so, bytes_read);
                metrics_inc_failure();
            }
            server_conn_cleanup(client_data); // Call cleanup
        }
    }
}

static void client_conn_write_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    client_data_t *client_data = (client_data_t *)nh->data;
    
    // Assert that client_data is within the pool range
    if (client_data < client_data_pool || client_data >= client_data_pool + CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("Invalid client_data pointer outside pool range: %p", client_data);
        return;
    }
    if (!client_data->in_use) {
        LOG_ERROR("client_data not marked as in use: %p", client_data);
        return;
    }

    int socket_error = netbsd_socket_error(nh);
    if (nh->so == NULL || client_data->cleaning_up || nh->is_closing || socket_error != 0) {
        LOG_DEBUG("Write callback ignored: socket closed, closing, or in error state (error=%d)", socket_error);
        server_conn_cleanup(client_data);
        return;
    }

    LOG_DEBUG("Client write callback triggered.");

    // First send the header if not sent
    if (!client_data->header_sent) {
        struct iovec header_iov;
        header_iov.iov_base = client_data->response_header + client_data->response_sent;
        header_iov.iov_len = client_data->header_size - client_data->response_sent;

        ssize_t bytes_written = netbsd_write(nh, &header_iov, 1);
        if (bytes_written > 0) {
            client_data->response_sent += bytes_written;
            scheduler_inc_stat(STAT_BYTES_SENT, bytes_written);
            LOG_INFO("Server: Sent %zd bytes of header (total %zu/%zu)", bytes_written, client_data->response_sent, client_data->header_size);

            if (client_data->response_sent >= client_data->header_size) {
                client_data->header_sent = 1;
                client_data->response_sent = 0; // Reset for body
                LOG_INFO("Server: Header fully sent");
            }
        } else if (bytes_written < 0) {
            if (bytes_written == -EAGAIN || bytes_written == -EWOULDBLOCK) {
                LOG_DEBUG("EAGAIN/EWOULDBLOCK during header write, will retry.");
            } else {
                if (bytes_written != -EPIPE) {
                    LOG_ERROR("Failed to write header: %s (errno: %d)", strerror(errno), errno);
                    metrics_inc_failure();
                }
                server_conn_cleanup(client_data);
            }
        }
        return;
    }

    // Header is sent, now send the body
    if (client_data->response_sent < client_data->response_size) {
        struct iovec body_iov;
        body_iov.iov_base = client_data->response_buffer + client_data->response_sent;
        size_t remaining = client_data->response_size - client_data->response_sent;
        body_iov.iov_len = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;

        ssize_t bytes_written = netbsd_write(nh, &body_iov, 1);
        if (bytes_written > 0) {
            client_data->response_sent += bytes_written;
            scheduler_inc_stat(STAT_BYTES_SENT, bytes_written);
            LOG_INFO("Server: Sent %zd bytes of body (total %zu/%zu)", bytes_written, client_data->response_sent, client_data->response_size);

            if (client_data->response_sent >= client_data->response_size) {
                LOG_INFO("Server: Response fully sent");
                metrics_inc_success(); // Increment success count when response is fully sent
                scheduler_inc_stat(STAT_REQUESTS_SENT, 1); // Use existing stat for responses sent
                // Response fully sent, wait for client to close or send another request
            }
        } else if (bytes_written < 0) {
            if (bytes_written == -EAGAIN || bytes_written == -EWOULDBLOCK) {
                LOG_DEBUG("EAGAIN/EWOULDBLOCK during body write, will retry.");
            } else {
                if (bytes_written != -EPIPE) {
                    LOG_ERROR("Failed to write response body: %s (errno: %d)", strerror(errno), errno);
                    metrics_inc_failure();
                }
                server_conn_cleanup(client_data);
            }
        }
    }
}

static void client_conn_close_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    client_data_t *client_data = (client_data_t *)nh->data;
    LOG_INFO("Client connection closed.");

    // Assert that client_data is within the pool range
    if (client_data < client_data_pool || client_data >= client_data_pool + CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("Invalid client_data pointer outside pool range: %p", client_data);
        return;
    }
    if (!client_data->in_use) {
        LOG_ERROR("client_data not marked as in use: %p", client_data);
        return;
    }

    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
    scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);

    return_client_data_to_pool(client_data);
}

static void server_conn_cleanup(client_data_t *client_data) {
    if (!client_data || client_data->cleaning_up) {
        return;
    }
    // Assert that client_data is within the pool range
    if (client_data < client_data_pool || client_data >= client_data_pool + CLIENT_DATA_POOL_SIZE) {
        LOG_ERROR("Invalid client_data pointer outside pool range: %p", client_data);
        return;
    }
    if (!client_data->in_use) {
        LOG_ERROR("client_data not marked as in use: %p", client_data);
        return;
    }
    client_data->cleaning_up = 1; // Set flag

    netbsd_close(&client_data->nh); // Close the netbsd handle
}
