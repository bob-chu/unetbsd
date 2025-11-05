#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ev.h>
#include <u_socket.h>

#include "client.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"
#include "deps/picohttpparser/picohttpparser.h"

extern struct ev_loop *g_main_loop;

// Structure to hold individual client connection data
struct client_conn_data {
    struct netbsd_handle nh;
    perf_config_t *config;
    char *send_buffer;
    size_t send_buffer_size;
    size_t sent_size;
    char *recv_buffer;
    size_t recv_buffer_size;
    double request_send_time;
    int is_connected;
    int cleaning_up; // New flag
    int local_port; // Assigned local port
    TAILQ_ENTRY(client_conn_data) entries;
    ev_timer request_timer;
    int requests_sent_on_connection;
    ev_timer conn_timeout_timer;
};

static int g_current_target_connections = 0;
static int g_current_target_total_connections = 0;
static double g_current_send_rate = 0.0; // packets per second
static int g_current_server_port_index = 0; // To cycle through server ports
static int g_server_port_count = 0; // Total number of server ports
static int *g_server_ports = NULL; // Array of server ports

// List to keep track of active TCP connections
static TAILQ_HEAD(tcp_conn_list_head, client_conn_data) g_tcp_conn_list;

static int *g_local_ports = NULL;
static int g_local_port_count = 0;
static int g_local_port_used = 0; // Number of ports currently in use
static int g_current_port_index = 0; // Current index for port allocation
static double g_last_port_stats_log_time = 0.0; // Last time port stats were logged

static ev_timer client_scheduler_watcher;
static ev_timer client_idle_watcher;
static void client_scheduler_cb(EV_P_ ev_timer *w, int revents);
static void client_idle_cb(EV_P_ ev_timer *w, int revents);


// Forward declarations for event callbacks
static void client_conn_connect_cb(void *handle, int events);
static void client_conn_read_cb(void *handle, int events);
static void client_conn_write_cb(void *handle, int events);
static void client_conn_close_cb(void *handle, int events);
static void client_request_timer_cb(EV_P_ ev_timer *w, int revents);
static void client_conn_timeout_cb(EV_P_ ev_timer *w, int revents);

static void client_conn_cleanup(struct ev_loop *loop, struct client_conn_data *conn_data);

static void create_tcp_connection(struct ev_loop *loop, perf_config_t *config);
static void send_udp_packet(struct ev_loop *loop, perf_config_t *config);
static void init_local_port_pool(perf_config_t *config);
static int get_local_port(void);
static void return_local_port(int port);

#include "client.h"

static void client_conn_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct client_conn_data *conn_data = (struct client_conn_data *)w->data;
    LOG_INFO("Connection to %s:%d timed out.",
              conn_data->config->network.dst_ip_start, conn_data->config->network.dst_port_start);
    metrics_inc_failure();
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
    LOG_DEBUG("client_conn_timeout_cb: STAT_CONCURRENT_CONNECTIONS decremented (timeout). Current: %lu", g_concurrent_connections);
    client_conn_cleanup(EV_A_ conn_data);
}
void run_client(struct ev_loop *loop, perf_config_t *config) {
    LOG_INFO("Starting client setup...");

    scheduler_init(loop, config);

    ev_timer_init(&client_scheduler_watcher, client_scheduler_cb, 0., 0.1); // Check every 100ms
    client_scheduler_watcher.data = config;
    ev_timer_start(loop, &client_scheduler_watcher);

    ev_timer_init(&client_idle_watcher, client_idle_cb, 0.1, 0.1); // Check every 100ms
    client_idle_watcher.data = config;
    ev_timer_start(loop, &client_idle_watcher);

    if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
        tcp_client_init(config);
    } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
        udp_client_init(config);
    } else {
        LOG_ERROR("Unsupported objective type: %s", config->objective.type);
    }
}



void tcp_client_init(perf_config_t *config) {
    LOG_INFO("TCP Client initialized.");
    TAILQ_INIT(&g_tcp_conn_list);
    init_local_port_pool(config);
}

void udp_client_init(perf_config_t *config) {
    LOG_INFO("UDP Client initialized.");
    init_local_port_pool(config);
}

static void client_scheduler_cb(EV_P_ ev_timer *w, int revents) {
    perf_config_t *config = (perf_config_t *)w->data;
    test_phase_t current_phase = scheduler_get_current_phase();

    switch (current_phase) {
        case PHASE_PREPARE:
            // Do nothing, just wait
            break;
        case PHASE_RAMP_UP: {
            double elapsed_in_phase = scheduler_get_current_time() - scheduler_get_current_phase_start_time();
            double progress = elapsed_in_phase / config->scheduler.ramp_up_duration_sec;
            if (progress > 1.0) progress = 1.0;

            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = (int)(config->objective.value * progress);
            } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
                g_current_target_total_connections = (int)(config->objective.value * progress);
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value * progress; // packets per second
                // Calculate number of packets to send in this interval
                double interval = ev_timer_remaining(EV_A_ &client_scheduler_watcher);
                int packets_to_send = (int)(g_current_send_rate * interval);
                for (int i = 0; i < packets_to_send; ++i) {
                    send_udp_packet(EV_A_ config);
                }
            }
            break;
        }
        case PHASE_SUSTAIN: {
            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = config->objective.value;
            } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
                g_current_target_total_connections = config->objective.value;
                if (scheduler_get_stats()->connections_opened >= g_current_target_total_connections) {
                    LOG_INFO("TOTAL_CONNECTIONS objective reached. Stopping client.");
                    scheduler_set_current_phase(PHASE_CLOSE);
                }
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value; // packets per second
                // Calculate number of packets to send in this interval
                double interval = ev_timer_remaining(EV_A_ &client_scheduler_watcher);
                int packets_to_send = (int)(g_current_send_rate * interval);
                for (int i = 0; i < packets_to_send; ++i) {
                    send_udp_packet(EV_A_ config);
                }
            }
            break;
        }
        case PHASE_RAMP_DOWN: {
            double elapsed_in_phase = scheduler_get_current_time() - scheduler_get_current_phase_start_time();
            double progress = elapsed_in_phase / config->scheduler.ramp_down_duration_sec;
            if (progress > 1.0) progress = 1.0;

            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0) {
                g_current_target_connections = (int)(config->objective.value * (1.0 - progress));
                // Logic to close connections if current > target
                while (g_concurrent_connections > g_current_target_connections && !TAILQ_EMPTY(&g_tcp_conn_list)) {
                    struct client_conn_data *conn_to_close = TAILQ_FIRST(&g_tcp_conn_list);
                    LOG_INFO("Closing TCP connection during RAMP_DOWN.");
                    client_conn_cleanup(EV_A_ conn_to_close);
                }
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value * (1.0 - progress); // packets per second
                // Logic to stop sending if rate is low
            }
            break;
        }
        case PHASE_CLOSE:
            g_current_target_connections = 0;
            g_current_send_rate = 0.0;
            // Logic to ensure all connections are closed
            while (!TAILQ_EMPTY(&g_tcp_conn_list)) {
                struct client_conn_data *conn_to_close = TAILQ_FIRST(&g_tcp_conn_list);
                LOG_INFO("Closing TCP connection during CLOSE phase.");
                client_conn_cleanup(EV_A_ conn_to_close);
            }
            break;
        case PHASE_FINISHED:
            LOG_INFO("Client scheduler received PHASE_FINISHED. Stopping client scheduler watcher and breaking event loop.");
            ev_timer_stop(EV_A_ w);
            ev_timer_stop(EV_A_ &client_idle_watcher);
            ev_break(EV_A_ EVBREAK_ALL); // Stop the event loop
            break;
    }
}

static void client_idle_cb(EV_P_ ev_timer *w, int revents) {
    perf_config_t *config = (perf_config_t *)w->data;
    double current_time = ev_now(EV_A);
    if (current_time - g_last_port_stats_log_time >= 1.0) { // Log every second
        if (g_local_port_used > g_local_port_count * 0.8) { // Warn if 80% of ports are used
            LOG_WARN("High local port usage: %d out of %d ports in use.", g_local_port_used, g_local_port_count);
        } else {
            LOG_DEBUG("Local port usage: %d out of %d ports in use.", g_local_port_used, g_local_port_count);
        }
        metrics_update_port_usage(g_local_port_used, g_local_port_count);
        g_last_port_stats_log_time = current_time;
    }
    if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
        while (g_concurrent_connections < g_current_target_connections) {
            create_tcp_connection(EV_A_ config);
        }
    } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
        while (scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
            create_tcp_connection(EV_A_ config);
        }
    }
}

static void create_tcp_connection(struct ev_loop *loop, perf_config_t *config) {
    struct client_conn_data *conn_data = (struct client_conn_data *)malloc(sizeof(struct client_conn_data));
    if (!conn_data) {
        LOG_ERROR("Failed to allocate memory for client connection data.");
        return;
    }
    memset(conn_data, 0, sizeof(struct client_conn_data));
    conn_data->config = config;
    conn_data->local_port = get_local_port();
    if (conn_data->local_port == -1) {
        LOG_ERROR("No available local ports for new connection.");
        free(conn_data);
        return;
    }
    ev_timer_init(&conn_data->request_timer, client_request_timer_cb, 0., 0.); // Initialize timer
    conn_data->request_timer.data = conn_data; // Set timer data to conn_data
    conn_data->requests_sent_on_connection = 0; // Initialize requests_sent_on_connection

    ev_timer_init(&conn_data->conn_timeout_timer, client_conn_timeout_cb, 10., 0.); // 10 second timeout
    conn_data->conn_timeout_timer.data = conn_data;
    ev_timer_start(g_main_loop, &conn_data->conn_timeout_timer);

    const char *request_path = config->http_config.client_request_path;
    conn_data->send_buffer_size = snprintf(NULL, 0, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);
    conn_data->send_buffer = (char *)malloc(conn_data->send_buffer_size + 1);
    if (!conn_data->send_buffer) {
        LOG_ERROR("Failed to allocate memory for client send buffer.");
        free(conn_data);
        return;
    }
    snprintf(conn_data->send_buffer, conn_data->send_buffer_size + 1, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);

    conn_data->recv_buffer_size = 2048; // 2K buffer for receiving data
    conn_data->recv_buffer = (char *)malloc(conn_data->recv_buffer_size);
    if (!conn_data->recv_buffer) {
        LOG_ERROR("Failed to allocate memory for client recv buffer.");
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }

    conn_data->nh.proto = PROTO_TCP;
    conn_data->nh.type = SOCK_STREAM;
    conn_data->nh.is_ipv4 = 1;

    if (netbsd_socket(&conn_data->nh) != 0) {
        LOG_ERROR("Failed to create client socket: %s", strerror(errno));
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }

    int optval = 1;
    if (netbsd_reuseaddr(&conn_data->nh, &optval, sizeof(optval))) {
        LOG_ERROR("Set reuseaddr option failed.");
        netbsd_close(&conn_data->nh);
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }

    // Bind to local port
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(conn_data->local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (netbsd_bind(&conn_data->nh, (struct sockaddr *)&local_addr) != 0) {
        LOG_ERROR("Failed to bind to local port %d: %s", conn_data->local_port, strerror(errno));
        netbsd_close(&conn_data->nh);
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }
    LOG_DEBUG("Bound to local port %d", conn_data->local_port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    int server_port = g_server_ports[g_current_server_port_index];
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    // Update the current server port index for the next connection
    g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;
    LOG_DEBUG("Connecting to server port %d", server_port);

    // Non-blocking connect
    int ret = netbsd_connect(&conn_data->nh, (struct sockaddr *)&server_addr);
    if (ret != 0 && ret != EINPROGRESS) {
        LOG_ERROR("Failed to connect from: %d to %s:%d: %d:%s", conn_data->local_port,
                  config->network.dst_ip_start, server_port, ret, strerror(ret));
        netbsd_close(&conn_data->nh);
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }
    conn_data->nh.data = conn_data; // Self-reference for callbacks
    conn_data->nh.write_cb = client_conn_connect_cb;
    netbsd_io_start(&conn_data->nh);
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, 1);
    LOG_DEBUG("create_tcp_connection: STAT_CONCURRENT_CONNECTIONS incremented. Current: %lu", g_concurrent_connections);
}

static void send_udp_packet(struct ev_loop *loop, perf_config_t *config) {
    struct client_conn_data *conn_data = (struct client_conn_data *)malloc(sizeof(struct client_conn_data));
    if (!conn_data) {
        LOG_ERROR("Failed to allocate memory for UDP client data.");
        return;
    }
    memset(conn_data, 0, sizeof(struct client_conn_data));
    conn_data->config = config;
    conn_data->local_port = get_local_port();
    if (conn_data->local_port == -1) {
        LOG_ERROR("No available local ports for UDP packet.");
        free(conn_data);
        return;
    }
    conn_data->send_buffer_size = config->client_payload.size;
    conn_data->send_buffer = (char *)malloc(conn_data->send_buffer_size);
    if (!conn_data->send_buffer) {
        LOG_ERROR("Failed to allocate memory for UDP send buffer.");
        free(conn_data);
        return;
    }
    memcpy(conn_data->send_buffer, config->client_payload.data, conn_data->send_buffer_size);

    conn_data->recv_buffer_size = 2048; // 2K buffer for receiving data
    conn_data->recv_buffer = (char *)malloc(conn_data->recv_buffer_size);
    if (!conn_data->recv_buffer) {
        LOG_ERROR("Failed to allocate memory for UDP recv buffer.");
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }

    conn_data->nh.proto = PROTO_UDP;
    conn_data->nh.type = SOCK_DGRAM;
    conn_data->nh.is_ipv4 = 1;

    if (netbsd_socket(&conn_data->nh) != 0) {
        LOG_ERROR("Failed to create UDP client socket: %s", strerror(errno));
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }

    // Bind to local port for UDP
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(conn_data->local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (netbsd_bind(&conn_data->nh, (struct sockaddr *)&local_addr) != 0) {
        LOG_ERROR("Failed to bind UDP socket to local port %d: %s", conn_data->local_port, strerror(errno));
        netbsd_close(&conn_data->nh);
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
        return;
    }
    LOG_DEBUG("UDP bound to local port %d", conn_data->local_port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    int server_port = g_server_ports[g_current_server_port_index];
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    // Update the current server port index for the next connection
    g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;
    LOG_DEBUG("Sending UDP packet to server port %d", server_port);

    struct iovec iov;
    iov.iov_base = conn_data->send_buffer;
    iov.iov_len = conn_data->send_buffer_size;

    conn_data->request_send_time = ev_now(loop);
    ssize_t bytes_sent = netbsd_sendto(&conn_data->nh, &iov, 1, (struct sockaddr *)&server_addr);

    if (bytes_sent > 0) {
        LOG_DEBUG("Sent %zd bytes UDP packet.", bytes_sent);
        scheduler_inc_stat(STAT_BYTES_SENT, bytes_sent);
        scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
        metrics_inc_success();

        // Now wait for a response
        conn_data->nh.data = conn_data; // Self-reference for callbacks
        conn_data->nh.read_cb = client_conn_read_cb;
        netbsd_io_start(&conn_data->nh);
    } else {
        LOG_ERROR("Failed to send UDP packet: %s", strerror(errno));
        metrics_inc_failure();
        netbsd_close(&conn_data->nh);
        free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        free(conn_data);
    }
}

static void client_conn_cleanup(struct ev_loop *loop, struct client_conn_data *conn_data) {
    if (!conn_data || conn_data->cleaning_up) {
        LOG_DEBUG("client_conn_cleanup: Already cleaning up or invalid conn_data.");
        return;
    }
    conn_data->cleaning_up = 1; // Set flag

    LOG_DEBUG("client_conn_cleanup: Entry point.");
    if (conn_data->nh.proto == PROTO_TCP) {
        if (conn_data->is_connected) { // Only remove if it was successfully connected
            TAILQ_REMOVE(&g_tcp_conn_list, conn_data, entries);
            scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
            LOG_DEBUG("client_conn_cleanup: STAT_CONCURRENT_CONNECTIONS decremented (cleanup). Current: %lu", g_concurrent_connections);
        }
        scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
    }
    LOG_DEBUG("client_conn_cleanup: Closing netbsd handle.");
    netbsd_close(&conn_data->nh);
    ev_timer_stop(g_main_loop, &conn_data->request_timer); // Stop request timer
    ev_timer_stop(g_main_loop, &conn_data->conn_timeout_timer); // Stop connection timeout timer
}

static void client_conn_connect_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    perf_config_t *config = conn_data->config;
    LOG_DEBUG("client_conn_connect_cb: Entry.nh: %p, so: %p",
              nh, nh->so);

    if (netbsd_socket_error(nh) == 0) {
        LOG_INFO("Successfully connected to %s:%d", config->network.dst_ip_start, config->network.dst_port_start);
        conn_data->is_connected = 1;
        scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
        TAILQ_INSERT_TAIL(&g_tcp_conn_list, conn_data, entries);
        LOG_DEBUG("client_conn_connect_cb: Connection established, callbacks set.");
        ev_timer_stop(g_main_loop, &conn_data->conn_timeout_timer); // Stop timeout timer on success

        // Set read, write and close callbacks
        nh->read_cb = client_conn_read_cb;
        nh->write_cb = client_conn_write_cb;
        nh->close_cb = client_conn_close_cb;
        // Start timer to send the first request
        ev_timer_set(&conn_data->request_timer, 0., 0.);
        ev_timer_start(g_main_loop, &conn_data->request_timer);
    } else {
        LOG_ERROR("Failed to connect to %s:%d: %s",
                  config->network.dst_ip_start, config->network.dst_port_start, strerror(errno));
        metrics_inc_failure();
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1); // Decrement for failed connection
        LOG_DEBUG("client_conn_connect_cb: STAT_CONCURRENT_CONNECTIONS decremented (failed connect). Current: %lu", g_concurrent_connections);
        client_conn_cleanup(g_main_loop, conn_data); // loop is not needed here
        // Try to create another connection if objective is TCP_CONCURRENT
        if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0) {
            create_tcp_connection(g_main_loop, config); // loop is not needed here
        }
    }
    LOG_DEBUG("client_conn_connect_cb: Exit.");
}

static void client_conn_write_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    LOG_INFO("client_conn_write_cb: Entry. nh: %p, so: %p",
             nh, nh->so);

    if (!conn_data || conn_data->cleaning_up) {
        return; // Connection is being cleaned up
    }

    perf_config_t *config = conn_data->config;
    if (config->objective.requests_per_connection > 0 &&
        conn_data->requests_sent_on_connection >= config->objective.requests_per_connection) {
        return; 
    }
    if (conn_data->sent_size == 0) { // First part of a new request
        conn_data->request_send_time = ev_now(g_main_loop);
    }

    struct iovec iov;
    iov.iov_base = conn_data->send_buffer + conn_data->sent_size;
    iov.iov_len = conn_data->send_buffer_size - conn_data->sent_size;

    ssize_t bytes_written = netbsd_write(nh, &iov, 1);

    if (bytes_written > 0) {
        conn_data->sent_size += bytes_written;
        scheduler_inc_stat(STAT_BYTES_SENT, bytes_written);
        LOG_INFO("client_conn_write_cb: Sent %zd bytes (total %zu/%zu).", bytes_written, conn_data->sent_size, conn_data->send_buffer_size);

        if (conn_data->sent_size == conn_data->send_buffer_size) {
            LOG_INFO("client_conn_write_cb: Full request sent.");
            scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
            conn_data->requests_sent_on_connection++; // Increment here
            conn_data->sent_size = 0; // Reset for the next request on this connection.

            // After writing, we expect a read event.
            // The read callback is already set, so we just wait.
        } else {
            LOG_DEBUG("client_conn_write_cb: Partial write, waiting for next writable event.");
            // Not fully sent, so we need to be called again.
            // The event loop will trigger us again when the socket is writable.
        }
    } else if (bytes_written < 0) {
        if (bytes_written != -EPIPE) {
            LOG_ERROR("client_conn_write_cb: Failed to write to socket: %s (errno: %d, bytes_written: %zd)", strerror(errno), errno, bytes_written);
            metrics_inc_failure();
        }
        LOG_DEBUG("client_conn_write_cb: Write failed, calling cleanup.");
        perf_config_t *config = conn_data->config;
        client_conn_cleanup(g_main_loop, conn_data);
        // Try to create another connection if objective is TCP_CONCURRENT
        if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0) {
            create_tcp_connection(g_main_loop, config);
        }
    } else { // bytes_written == 0
        LOG_WARN("Zero bytes written, but data was available.");
    }
    LOG_DEBUG("client_conn_write_cb: Exit.");
}

static void client_conn_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    LOG_DEBUG("client_conn_read_cb: Entry. nh: %p, so: %p",
              nh, nh->so);

    if (!conn_data || conn_data->cleaning_up) {
        return; // Connection is being cleaned up
    }

    perf_config_t *config = conn_data->config;

    struct iovec iov;
    iov.iov_base = conn_data->recv_buffer;
    iov.iov_len = conn_data->recv_buffer_size;

    ssize_t bytes_read;
    if (nh->proto == PROTO_TCP) {
        bytes_read = netbsd_read(nh, &iov, 1);
    } else { // UDP
        struct sockaddr_in server_addr;
        bytes_read = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&server_addr);
    }

    if (bytes_read > 0) {
        LOG_INFO("client_conn_read_cb: Received %zd bytes: %s.", bytes_read, conn_data->recv_buffer);
        scheduler_inc_stat(STAT_BYTES_RECEIVED, bytes_read);
        scheduler_inc_stat(STAT_RESPONSES_RECEIVED, 1);

        int pret, minor_version, status;
        const char *msg;
        size_t msg_len;
        struct phr_header headers[100];
        size_t num_headers;

        num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_response(conn_data->recv_buffer, bytes_read, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

        if (pret > 0) { // successful parse
            LOG_INFO("HTTP Response: %d %.*s", status, (int)msg_len, msg);

            double response_recv_time = ev_now(g_main_loop);
            uint64_t latency_ms = (uint64_t)((response_recv_time - conn_data->request_send_time) * 1000);
            metrics_add_latency(latency_ms);
            metrics_inc_success(); // Increment success for a completed request-response cycle

            // Check if we should keep the connection busy for HTTP requests
            if (strcmp(config->objective.type, "HTTP_REQUESTS") == 0 && config->objective.requests_per_connection == 0) {
                // Reset for next request and immediately send another one
                conn_data->sent_size = 0;
                conn_data->requests_sent_on_connection++;
                client_conn_write_cb(&conn_data->nh, 0);
            } else if (config->objective.requests_per_connection > 0 &&
                       conn_data->requests_sent_on_connection >= config->objective.requests_per_connection) {
                LOG_INFO("client_conn_read_cb: Reached requests_per_connection limit (%d). Closing connection.",
                         config->objective.requests_per_connection);
                client_conn_cleanup(g_main_loop, conn_data);
            } else {
                // For other objectives or if requests_per_connection is not met, close the connection.
                client_conn_cleanup(g_main_loop, conn_data);
            }
        } else if (pret == -1) { // parse error
            LOG_ERROR("HTTP parse error in response");
            metrics_inc_failure();
            client_conn_cleanup(g_main_loop, conn_data);
        } else { // incomplete response
            LOG_DEBUG("Incomplete HTTP response");
            // For this tool, we assume full response in one read and close
            client_conn_cleanup(g_main_loop, conn_data);
        }
    } else if (bytes_read == 0) {
        LOG_INFO("client_conn_read_cb: Server closed connection.");
        LOG_DEBUG("client_conn_read_cb: Calling cleanup.");
        ev_timer_stop(g_main_loop, &conn_data->request_timer); // Stop timer on close
        //metrics_inc_failure(); // Increment failure if server closes connection
        client_conn_cleanup(g_main_loop, conn_data);
        if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0) {
            create_tcp_connection(g_main_loop, config);
        }
    } else {
        /*
        if (bytes_read == -EAGAIN || bytes_read == -EWOULDBLOCK) {
            return;
        }
        */
        //LOG_ERROR("client_conn_read_cb: Failed to read from socket: %s (errno: %d, bytes_read: %zd)", strerror(-bytes_read), -bytes_read, bytes_read);
        if (bytes_read != -EPIPE) {
            metrics_inc_failure();
        }
        LOG_DEBUG("client_conn_read_cb: Calling cleanup on read error.");
        ev_timer_stop(g_main_loop, &conn_data->request_timer); // Stop timer on error
        client_conn_cleanup(g_main_loop, conn_data);
        if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0) {
            create_tcp_connection(g_main_loop, config);
        }
    }
    LOG_DEBUG("client_conn_read_cb: Exit.");
}

static void client_conn_close_cb(void *handle, int events) {
    LOG_DEBUG("client_conn_close_cb: Entry point.");
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    LOG_INFO("Client connection closed.");

    if (!conn_data) {
        LOG_WARN("client_conn_close_cb: conn_data is NULL, nothing to cleanup.");
        return;
    }

    test_phase_t current_phase = scheduler_get_current_phase();

    // Try to create another connection if objective is TCP_CONCURRENT and we are in RAMP_UP or SUSTAIN phase
    if (strcmp(conn_data->config->objective.type, "TCP_CONCURRENT") == 0 &&
        (current_phase == PHASE_RAMP_UP || current_phase == PHASE_SUSTAIN)) {
        create_tcp_connection(g_main_loop, conn_data->config);
    }

    LOG_DEBUG("client_conn_close_cb: Freeing resources");
    if (conn_data->recv_buffer) {
        free(conn_data->recv_buffer);
    }
    if (conn_data->send_buffer) {
        free(conn_data->send_buffer);
    }
    ev_timer_stop(g_main_loop, &conn_data->request_timer); // Stop timer
    return_local_port(conn_data->local_port); // Return the local port to the pool
    LOG_DEBUG("Returned local port %d to pool", conn_data->local_port);
    free(conn_data);
    LOG_DEBUG("client_conn_close_cb: Exit.");
}

static void client_request_timer_cb(EV_P_ ev_timer *w, int revents) {
    struct client_conn_data *conn_data = (struct client_conn_data *)w->data;
    // Ensure the connection is still valid before attempting to write
    if (conn_data && !conn_data->cleaning_up) {
        // Call client_conn_write_cb to send the next request
        client_conn_write_cb(&conn_data->nh, 0);
    }
}

int client_get_current_target_connections(void) {
    return g_current_target_connections;
}

uint64_t client_get_local_ports_used(void) {
    return g_local_port_used;
}

uint64_t client_get_total_local_ports(void) {
    return g_local_port_count;
}

static void init_local_port_pool(perf_config_t *config) {
    int start_port = config->network.src_port_start;
    int end_port = config->network.src_port_end;
    g_local_port_count = end_port - start_port + 1;
    
    // Allocate an array for local ports
    g_local_ports = (int *)malloc(g_local_port_count * sizeof(int));
    if (!g_local_ports) {
        LOG_ERROR("Failed to allocate memory for local ports array.");
        g_local_port_count = 0;
        return;
    }
    
    for (int i = 0; i < g_local_port_count; i++) {
        g_local_ports[i] = start_port + i;
    }
    g_local_port_used = 0;
    g_current_port_index = 0;
    g_last_port_stats_log_time = 0.0;
    LOG_INFO("Initialized local port pool with %d ports (%d to %d).", g_local_port_count, start_port, end_port);

    // Initialize server ports array
    g_server_port_count = config->network.dst_port_end - config->network.dst_port_start + 1;
    g_server_ports = (int *)malloc(g_server_port_count * sizeof(int));
    if (!g_server_ports) {
        LOG_ERROR("Failed to allocate memory for server ports array.");
        g_server_port_count = 0;
        return;
    }
    for (int i = 0; i < g_server_port_count; i++) {
        g_server_ports[i] = config->network.dst_port_start + i;
    }
    LOG_INFO("Initialized server port pool with %d ports (%d to %d).", g_server_port_count, config->network.dst_port_start, config->network.dst_port_end);
}

static int get_local_port(void) {
    if (g_local_port_used >= g_local_port_count) {
        LOG_WARN("No more local ports available in pool, reusing ports.");
        // Reset the index to allow reuse of ports
        g_current_port_index = 0;
        g_local_port_used = 0;
    }
    int port = g_local_ports[g_current_port_index];
    LOG_DEBUG("Getting port %d from pool (index %d)", port, g_current_port_index);
    g_current_port_index = (g_current_port_index + 1) % g_local_port_count;
    g_local_port_used++;
    return port;
}

static void return_local_port(int port) {
    if (g_local_port_used <= 0) {
        LOG_WARN("Returning port %d to pool, but no ports are in use.", port);
        return;
    }
    LOG_DEBUG("Returning port %d to pool", port);
    g_local_port_used--;
}
