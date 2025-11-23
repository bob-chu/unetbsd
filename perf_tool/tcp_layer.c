#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ev.h>
#include <u_socket.h>

#include "tcp_layer.h"
#include "logger.h"
#include "metrics.h"

#define MAX_RECV_SZ 7000
#define RECV_BUFFER_SZ 8192

int g_current_server_port_index = 0;
int g_server_port_count = 0;
int *g_server_ports = NULL;

static int *g_local_ports = NULL;
static int g_local_port_count = 0;
static int g_local_port_used = 0;
static int g_current_port_index = 0;
static double g_last_port_stats_log_time = 0.0;

static tcp_server_callbacks_t *g_server_callbacks = NULL;

typedef struct listen_watcher_data {
    struct netbsd_handle listen_nh;
} listen_watcher_data_t;

static listen_watcher_data_t *listen_datas = NULL;
static int num_listen_ports = 0;

static void tcp_layer_connect_cb(void *handle, int events);
static void tcp_layer_read_cb(void *handle, int events);
static void tcp_layer_write_cb(void *handle, int events);
static void tcp_layer_timeout_cb(EV_P_ ev_timer *w, int revents);
static void tcp_layer_accept_cb(void *handle, int events);
static void tcp_layer_close_cb(void *handle, int events);

void tcp_layer_init_local_port_pool(perf_config_t *config) {
    int start_port = config->network.src_port_start;
    int end_port = config->network.src_port_end;
    g_local_port_count = end_port - start_port + 1;
    
    g_local_ports = (int *)malloc(g_local_port_count * sizeof(int));
    if (!g_local_ports) {
        g_local_port_count = 0;
        return;
    }
    
    for (int i = 0; i < g_local_port_count; i++) {
        g_local_ports[i] = start_port + i;
    }
    g_local_port_used = 0;
    g_current_port_index = 0;
    g_last_port_stats_log_time = 0.0;

    g_server_port_count = config->network.dst_port_end - config->network.dst_port_start + 1;
    g_server_ports = (int *)malloc(g_server_port_count * sizeof(int));
    if (!g_server_ports) {
        g_server_port_count = 0;
        return;
    }
    for (int i = 0; i < g_server_port_count; i++) {
        g_server_ports[i] = config->network.dst_port_start + i;
    }
    g_current_server_port_index = 0;
}

int tcp_layer_get_local_port(void) {
    if (g_local_port_used >= g_local_port_count) {
        g_current_port_index = 0;
    }
    int port = g_local_ports[g_current_port_index];
    g_current_port_index = (g_current_port_index + 1) % g_local_port_count;
    g_local_port_used++;
    return port;
}

void tcp_layer_return_local_port(int port) {
    if (g_local_port_used <= 0) {
        return;
    }
    g_local_port_used--;
}

uint64_t tcp_layer_get_local_ports_used(void) {
    return g_local_port_used;
}

uint64_t tcp_layer_get_total_local_ports(void) {
    return g_local_port_count;
}

void tcp_layer_update_port_stats_if_needed(double current_time) {
    if (current_time - g_last_port_stats_log_time >= 1.0) {
        metrics_update_port_usage(g_local_port_used, g_local_port_count);
        g_last_port_stats_log_time = current_time;
    }
}

int tcp_layer_connect(struct ev_loop *loop, perf_config_t *config, int unused, tcp_callbacks_t *callbacks, void *upper_layer_data, tcp_conn_t **conn_out) {
    LOG_DEBUG("tcp_layer_connect start......");
    tcp_conn_t *conn = (tcp_conn_t *)malloc(sizeof(tcp_conn_t));
    if (!conn) {
        return -1;
    }
    memset(conn, 0, sizeof(tcp_conn_t));

    conn->loop = loop;
    conn->callbacks = *callbacks;
    conn->upper_layer_data = upper_layer_data;

    conn->nh.proto = PROTO_TCP;
    conn->nh.type = SOCK_STREAM;
    conn->nh.is_ipv4 = 1;
    conn->nh.read_cb = NULL;
    conn->nh.write_cb = NULL;
    conn->nh.close_cb = NULL;
    conn->nh.data = NULL;
    conn->nh.active = 0;
    conn->nh.is_closing = 0;
    conn->nh.events = 0;
    conn->nh.on_event_queue = 0;

    if (netbsd_socket(&conn->nh) != 0) {
        free(conn);
        return -1;
    }

    int optval = 1;
    netbsd_reuseaddr(&conn->nh, &optval, sizeof(optval));

    int local_port = tcp_layer_get_local_port();
    if (local_port == -1) {
        netbsd_close(&conn->nh);
        free(conn);
        return -1;
    }
    conn->local_port = local_port;

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (netbsd_bind(&conn->nh, (struct sockaddr *)&local_addr) != 0) {
        LOG_ERROR("Failed to bind TCP socket to local port %d: %s", local_port, strerror(errno));
        tcp_layer_return_local_port(local_port);
        netbsd_close(&conn->nh);
        free(conn);
        return -1;
    }

    // Cycle through destination ports
    int server_port = g_server_ports[g_current_server_port_index];
    g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    LOG_DEBUG("Connecting to server port: %d, from: %d", server_port, local_port);
    int ret = netbsd_connect(&conn->nh, (struct sockaddr *)&server_addr);
    if (ret != 0 && ret != EINPROGRESS) {
        LOG_ERROR("Failed to connect TCP socket to port %d: %s", server_port, strerror(errno));
        tcp_layer_return_local_port(local_port);
        netbsd_close(&conn->nh);
        free(conn);
        return -1;
    }

    conn->nh.data = conn;
    conn->nh.write_cb = tcp_layer_connect_cb;
    conn->nh.close_cb = tcp_layer_close_cb;
    netbsd_io_start(&conn->nh);
    LOG_DEBUG("tcp_layer_connect set tcp_layer_connct_cb on write_cb");

    ev_timer_init(&conn->conn_timeout_timer, tcp_layer_timeout_cb, 100., 0.);
    conn->conn_timeout_timer.data = conn;
    ev_timer_start(conn->loop, &conn->conn_timeout_timer);

    *conn_out = conn;
    return 0;
}

ssize_t tcp_layer_write(tcp_conn_t *conn, const char *data, size_t len) {
    struct iovec iov;
    iov.iov_base = (void *)data;
    iov.iov_len = len;
    LOG_DEBUG("TCP layer netbsd_write: %d:%s", len, data);
    return netbsd_write(&conn->nh, &iov, 1);
}

void tcp_layer_close(tcp_conn_t *conn) {
    if (conn && !conn->nh.is_closing) {
        ev_timer_stop(conn->loop, &conn->conn_timeout_timer);

        conn->nh.read_cb = NULL;
        conn->nh.write_cb = NULL;
        conn->nh.close_cb = tcp_layer_close_cb;
        conn->nh.data = conn;
        conn->nh.active = 0;
        conn->nh.is_closing = 1;
#if 0
        // If on_close callback is set, call it to notify upper layer
        if (conn->callbacks.on_close) {
            conn->callbacks.on_close(conn);
            // Prevent further callbacks by clearing it after calling
            conn->callbacks.on_close = NULL;
        }
#endif
        netbsd_close(&conn->nh);
        // Do not free(conn) here as it will be done in close_cb when triggered by netbsd_close
    }
}

static void tcp_layer_close_cb(void *handle, int events) {
    LOG_DEBUG("Entering tcp_layer_close_cb with events: %d", events);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    LOG_DEBUG("netbsd_handle: %p", nh);
    tcp_conn_t *conn = (tcp_conn_t *)nh->data;
    
    if (conn && nh->data) {
        // Ensure the connection is marked as closing
        conn->nh.is_closing = 1;
        // Stop any timers associated with this connection
        ev_timer_stop(conn->loop, &conn->conn_timeout_timer);
        // Call upper layer close callback if not already called
        if (conn->callbacks.on_close) {
            conn->callbacks.on_close(conn);
            conn->callbacks.on_close = NULL; // Prevent double call
        }
        // Return local port if it hasn't been returned yet
        if (conn->local_port > 0) {
            tcp_layer_return_local_port(conn->local_port);
            conn->local_port = 0;
        }
        // Clear the handle data to prevent further use
        nh->data = NULL;
        // Free the connection structure
        free(conn);
    }
}

int tcp_layer_server_init(perf_config_t *config, tcp_server_callbacks_t *callbacks) {
    g_server_callbacks = callbacks;

    int dst_port_start = config->network.dst_port_start;
    int dst_port_end = config->network.dst_port_end;
    num_listen_ports = dst_port_end - dst_port_start + 1;
    if (num_listen_ports <= 0) {
        LOG_ERROR("Invalid port range: start=%d, end=%d", dst_port_start, dst_port_end);
        return -1;
    }

    listen_datas = malloc(num_listen_ports * sizeof(listen_watcher_data_t));
    if (!listen_datas) {
        LOG_ERROR("Failed to allocate listen data array");
        return -1;
    }
    memset(listen_datas, 0, num_listen_ports * sizeof(listen_watcher_data_t));

    int success_count = 0;
    for (int i = 0; i < num_listen_ports; i++) {
        int port = dst_port_start + i;
        listen_watcher_data_t *listen_data = &listen_datas[i];

        listen_data->listen_nh.proto = PROTO_TCP;
        listen_data->listen_nh.type = SOCK_STREAM;
        listen_data->listen_nh.is_ipv4 = 1;
        listen_data->listen_nh.read_cb = tcp_layer_accept_cb;
        listen_data->listen_nh.write_cb = NULL;
        listen_data->listen_nh.close_cb = tcp_layer_close_cb;
        listen_data->listen_nh.data = listen_data;
        listen_data->listen_nh.active = 0;
        listen_data->listen_nh.is_closing = 0;
        listen_data->listen_nh.events = 0;
        listen_data->listen_nh.on_event_queue = 0;

        int ret = netbsd_socket(&listen_data->listen_nh);
        if (ret != 0) {
            LOG_ERROR("Failed to create listen socket for port %d: %d", port, ret);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (netbsd_bind(&listen_data->listen_nh, (struct sockaddr *)&addr) != 0) {
            LOG_ERROR("Failed to bind listen socket for port %d", port);
            netbsd_close(&listen_data->listen_nh);
            continue;
        }

        if (netbsd_listen(&listen_data->listen_nh, SOMAXCONN) != 0) {
            LOG_ERROR("Failed to listen on socket for port %d", port);
            netbsd_close(&listen_data->listen_nh);
            continue;
        }

        netbsd_io_start(&listen_data->listen_nh);
        LOG_INFO("TCP Server listening on port %d", port);
        success_count++;
    }

    if (success_count == 0) {
        LOG_ERROR("No listen sockets successfully initialized");
        free(listen_datas);
        listen_datas = NULL;
        num_listen_ports = 0;
        return -1;
    }

    return 0;
}

void tcp_layer_server_cleanup(perf_config_t *config) {
    if (listen_datas) {
        for (int i = 0; i < num_listen_ports; i++) {
            netbsd_close(&listen_datas[i].listen_nh);
        }
        free(listen_datas);
        listen_datas = NULL;
        num_listen_ports = 0;
    }
    g_server_callbacks = NULL;
}

static void tcp_layer_accept_cb(void *handle, int events) {
    LOG_DEBUG("Entering tcp_layer_accept_cb with events: %d", events);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;

    struct netbsd_handle *listen_nh = (struct netbsd_handle *)handle;

    while (1) {
        tcp_conn_t *conn = (tcp_conn_t *)malloc(sizeof(tcp_conn_t));
        if (!conn) {
            break;
        }
        memset(conn, 0, sizeof(tcp_conn_t));

        conn->nh.proto = PROTO_TCP;
        conn->nh.type = SOCK_STREAM;
        conn->nh.is_ipv4 = 1;
        conn->nh.read_cb = tcp_layer_read_cb;
        conn->nh.write_cb = tcp_layer_write_cb;
        conn->nh.close_cb = tcp_layer_close_cb;
        conn->nh.data = conn;
        conn->nh.active = 1;
        conn->nh.is_closing = 0;
        conn->nh.events = 0;
        conn->nh.on_event_queue = 0;

        int ret = netbsd_accept(listen_nh, &conn->nh);
        if (ret != 0) {
            free(conn);
            break;
        }
        LOG_DEBUG("tcp accept on tcp_layer, nh: %p, nh->so: %p", &conn->nh, conn->nh.so);

        netbsd_io_start(&conn->nh);

        if (g_server_callbacks->on_accept) {
            g_server_callbacks->on_accept(conn);
        }
    }
}

static void tcp_layer_connect_cb(void *handle, int events) {
    LOG_DEBUG("Entering tcp_layer_connect_cb with events: %d", events);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    LOG_DEBUG("netbsd_handle: %p", nh);
    tcp_conn_t *conn = (tcp_conn_t *)nh->data;

    int socket_err = netbsd_socket_error(nh);
    if (socket_err == 0) {
        conn->is_connected = 1;
        ev_timer_stop(conn->loop, &conn->conn_timeout_timer);
        nh->read_cb = tcp_layer_read_cb;
        nh->write_cb = tcp_layer_write_cb;
        nh->close_cb = tcp_layer_close_cb;
        if (conn->callbacks.on_connect) {
            conn->callbacks.on_connect(conn, 0);
        }
    } else {
        if (conn->callbacks.on_connect) {
            conn->callbacks.on_connect(conn, socket_err);
        }
        tcp_layer_close(conn);
    }
}

static void tcp_layer_read_cb(void *handle, int events) {
    LOG_DEBUG("Entering tcp_layer_read_cb with events: %d", events);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    LOG_DEBUG("netbsd_handle: %p", nh);
    tcp_conn_t *conn = (tcp_conn_t *)nh->data;
    char buffer[RECV_BUFFER_SZ];
    struct iovec iov;

    while (1) {
        iov.iov_base = buffer;
        iov.iov_len = MAX_RECV_SZ;
        ssize_t bytes_read = netbsd_read(nh, &iov, 1);
        LOG_DEBUG("tcp_layer_read_cb : %zd", bytes_read);
        if (bytes_read > 0) {
            // Null-terminate for safe logging
            buffer[bytes_read] = '\0';
            LOG_DEBUG("tcp_layer_read_cb : %s", buffer);
            if (conn->callbacks.on_read) {
                conn->callbacks.on_read(conn, buffer, bytes_read);
            }
            if (bytes_read == MAX_RECV_SZ) {
                continue;
            } else {
                return;
            }
        } else {
            LOG_DEBUG("tcp_layer_read_cb return : %d", bytes_read);
            if (bytes_read == -35 /* EAGAIN */) {
                return;
            }
            if (conn->callbacks.on_read) {
                conn->callbacks.on_read(conn, NULL, bytes_read);
            }
            // If read returns <= 0, it might indicate a connection closure or error
            if (bytes_read < 0) {
                LOG_DEBUG("tcp_layer_read_cb return : %d, close tcp", bytes_read);
                tcp_layer_close(conn);
                return;
            }
        }
    }
}

static void tcp_layer_write_cb(void *handle, int events) {
    LOG_DEBUG("Entering tcp_layer_write_cb with events: %d", events);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    LOG_DEBUG("netbsd_handle: %p", nh);

    tcp_conn_t *conn = (tcp_conn_t *)nh->data;
    if (conn->callbacks.on_write) {
        conn->callbacks.on_write(conn);
    }
}

static void tcp_layer_timeout_cb(EV_P_ ev_timer *w, int revents) {
    LOG_DEBUG("Entering tcp_layer_timeout_cb");
    tcp_conn_t *conn = (tcp_conn_t *)w->data;
    if (conn) {
        LOG_DEBUG("netbsd_handle: %p", &conn->nh);
        // Stop the timer first to prevent further triggers
        ev_timer_stop(conn->loop, w);
        if (conn->callbacks.on_connect) {
            conn->callbacks.on_connect(conn, ETIMEDOUT);
            // Clear callback to prevent further calls
            conn->callbacks.on_connect = NULL;
        }
        tcp_layer_close(conn);
    }
}
