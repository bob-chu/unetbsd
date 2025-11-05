#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

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

// Structure to hold client-specific data
typedef struct {
    struct netbsd_handle nh;
    perf_config_t *config;
    char *recv_buffer;
    size_t recv_buffer_size;
    struct sockaddr_in remote_addr;
    socklen_t remote_addr_len;
    int cleaning_up; // New flag
} client_data_t;

typedef struct {
    struct netbsd_handle listen_nh;
    perf_config_t *config;
} listen_watcher_data_t;

static void server_conn_cleanup(client_data_t *client_data);

void run_server(struct ev_loop *loop, perf_config_t *config) {
    LOG_INFO("Starting server setup...");

    scheduler_init(loop, config);

    listen_watcher_data_t *listen_data = (listen_watcher_data_t *)malloc(sizeof(listen_watcher_data_t));
    if (!listen_data) {
        LOG_ERROR("Failed to allocate memory for listen data.");
        return;
    }
    memset(listen_data, 0, sizeof(listen_watcher_data_t));
    listen_data->config = config;

    listen_data->listen_nh.proto = (strcmp(config->network.protocol, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
    listen_data->listen_nh.type = SOCK_STREAM; // For TCP, will be SOCK_DGRAM for UDP
    listen_data->listen_nh.is_ipv4 = 1; // Assuming IPv4 for now

    if (netbsd_socket(&listen_data->listen_nh) != 0) {
        LOG_ERROR("Failed to create listen socket: %s", strerror(errno));
        free(listen_data);
        return;
    }
    LOG_DEBUG("listen socket: nh: %p, so: %p\n", &listen_data->listen_nh, listen_data->listen_nh.so);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->network.dst_port_start);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    if (netbsd_bind(&listen_data->listen_nh, (struct sockaddr *)&server_addr) != 0) {
        LOG_ERROR("Failed to bind listen socket to %s:%d: %s",
                  config->network.dst_ip_start, config->network.dst_port_start, strerror(errno));
        netbsd_close(&listen_data->listen_nh);
        free(listen_data);
        return;
    }

    if (listen_data->listen_nh.proto == PROTO_TCP) {
        if (netbsd_listen(&listen_data->listen_nh, 128) != 0) { // Backlog of 128
            LOG_ERROR("Failed to listen on socket: %s", strerror(errno));
            netbsd_close(&listen_data->listen_nh);
            free(listen_data);
            return;
        }
        LOG_INFO("Server listening on %s:%d (TCP)", config->network.dst_ip_start, config->network.dst_port_start);
        listen_data->listen_nh.read_cb = server_listen_read_cb;
        listen_data->listen_nh.data = listen_data;
        netbsd_io_start(&listen_data->listen_nh);
    } else { // UDP
        LOG_INFO("Server listening on %s:%d (UDP)", config->network.dst_ip_start, config->network.dst_port_start);
        // For UDP, the listen socket is also the data socket.
        client_data_t *udp_client_data = (client_data_t *)malloc(sizeof(client_data_t));
        if (!udp_client_data) {
            LOG_ERROR("Failed to allocate memory for UDP client data.");
            netbsd_close(&listen_data->listen_nh);
            free(listen_data);
            return;
        }
        memset(udp_client_data, 0, sizeof(client_data_t));
        memcpy(&udp_client_data->nh, &listen_data->listen_nh, sizeof(struct netbsd_handle));
        udp_client_data->config = config;
        udp_client_data->recv_buffer_size = (config->client_payload.size > config->server_response.size ?
                                             config->client_payload.size : config->server_response.size) < 2048 ?
                                             2048 : (config->client_payload.size > config->server_response.size ?
                                                     config->client_payload.size : config->server_response.size); // Ensure minimum 2K buffer
        udp_client_data->recv_buffer = (char *)malloc(udp_client_data->recv_buffer_size);
        if (!udp_client_data->recv_buffer) {
            LOG_ERROR("Failed to allocate memory for UDP receive buffer.");
            free(udp_client_data);
            netbsd_close(&listen_data->listen_nh);
            free(listen_data);
            return;
        }
        udp_client_data->nh.data = udp_client_data; // Self-reference for callbacks
        udp_client_data->nh.read_cb = client_conn_read_cb;
        netbsd_io_start(&udp_client_data->nh);
    }
}

static void server_listen_read_cb(void *handle, int events) {
    listen_watcher_data_t *listen_data = (listen_watcher_data_t *)((struct netbsd_handle *)handle)->data;
    struct netbsd_handle *listen_nh = &listen_data->listen_nh;
    perf_config_t *config = listen_data->config;
    int ret = 0;

    while (1) {
        client_data_t *client_data = (client_data_t *)malloc(sizeof(client_data_t));
        if (!client_data) {
            LOG_ERROR("Failed to allocate memory for client data.");
            break;
        }
        memset(client_data, 0, sizeof(client_data_t));
        client_data->config = config;
        client_data->recv_buffer_size = (strcmp(config->objective.type, "HTTP_REQUESTS") == 0 || config->client_payload.size < 2048) ? 2048 : config->client_payload.size; // Ensure minimum 2K buffer
        client_data->recv_buffer = (char *)malloc(client_data->recv_buffer_size);
        if (!client_data->recv_buffer) {
            LOG_ERROR("Failed to allocate memory for client receive buffer.");
            free(client_data);
            break;
        }
        client_data->nh.data = client_data; // Self-reference for callbacks

        if ((ret = netbsd_accept(listen_nh, &client_data->nh)) != 0) {
            free(client_data->recv_buffer);
            free(client_data);
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
    perf_config_t *config = client_data->config;

    struct iovec iov;
    iov.iov_base = client_data->recv_buffer;
    iov.iov_len = client_data->recv_buffer_size;

    int bytes_read;
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
            const char *response_body_1 = "<html><body><h1>Hello, World!</h1></body></html>";
            const char *response_body_2 = "<html><body><h1>Another page</h1></body></html>";
            const char *response_404 = "<html><body><h1>404 Not Found</h1></body></html>";

            char response_header[256];
            int content_length;
            const char *response_body;
            int status_code = 200;

            if (strncmp(path, "/hello", path_len) == 0) {
                response_body = response_body_1;
                content_length = strlen(response_body_1);
            } else if (strncmp(path, "/another", path_len) == 0) {
                response_body = response_body_2;
                content_length = strlen(response_body_2);
            } else {
                response_body = response_404;
                content_length = strlen(response_404);
                status_code = 404;
            }

            int header_len = snprintf(response_header, sizeof(response_header),
                "HTTP/1.1 %d OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "\r\n",
                status_code, content_length);

            struct iovec response_iov[2];
            response_iov[0].iov_base = response_header;
            response_iov[0].iov_len = header_len;
            response_iov[1].iov_base = (void *)response_body;
            response_iov[1].iov_len = content_length;

            ssize_t bytes_written = netbsd_write(nh, response_iov, 2);

            if (bytes_written > 0) {
                LOG_INFO("Sent %zd bytes in response.", bytes_written);
                scheduler_inc_stat(STAT_BYTES_SENT, bytes_written);
                metrics_inc_success();
                // return, wait for client side close it
                return;
            } else if (bytes_written < 0) {
                if (bytes_written != -EPIPE) {
                    LOG_ERROR("Failed to write response: %s", strerror(errno));
                    metrics_inc_failure();
                }
            }
            server_conn_cleanup(client_data);
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
        //LOG_ERROR("Failed to read from socket: %s", strerror(errno));
        if (bytes_read != -EPIPE) {
            /* closed by other side */
            metrics_inc_failure();
        }
        server_conn_cleanup(client_data); // Call cleanup
    }
}

static void client_conn_write_cb(void *handle, int events) {
    // Not strictly needed for a simple echo server, but good to have for completeness
    // In a more complex scenario, this would handle pending writes.
    LOG_DEBUG("Client write callback triggered.");
}

static void client_conn_close_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    client_data_t *client_data = (client_data_t *)nh->data;
    LOG_INFO("Client connection closed.");

    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
    scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);

    if (client_data->recv_buffer) {
        free(client_data->recv_buffer);
    }
    free(client_data);
}

static void server_conn_cleanup(client_data_t *client_data) {
    if (!client_data || client_data->cleaning_up) {
        return;
    }
    client_data->cleaning_up = 1; // Set flag

    netbsd_close(&client_data->nh); // Close the netbsd handle
}
