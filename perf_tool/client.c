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

#define MAX_RECV_SIZE 2048
// Structure to hold individual client connection data
struct client_conn_data {
    struct netbsd_handle nh;
    perf_config_t *config;
    char *send_buffer;
    size_t send_buffer_size;
    size_t sent_size;
    char recv_buffer[MAX_RECV_SIZE];;
    size_t recv_buffer_size;
    size_t total_received; // Total bytes received for current response
    size_t data_received;  // Bytes of data received in recv_buffer (excluding any processed data)
    size_t header_length;  // Length of parsed headers
    long long content_length; // Expected content length from headers
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

// Pool for preallocated client_conn_data structures
#define CLIENT_CONN_POOL_SIZE 8000 
static struct client_conn_data *g_client_conn_pool = NULL;
static int g_client_conn_pool_used = 0;

// List to keep track of available client_conn_data in the pool
static TAILQ_HEAD(client_conn_pool_head, client_conn_data) g_client_conn_pool_list;

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

static void client_conn_timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct client_conn_data *conn_data = (struct client_conn_data *)w->data;
    LOG_INFO("Connection to %s:%d timed out.",
              conn_data->config->network.dst_ip_start, conn_data->config->network.dst_port_start);
    metrics_inc_failure();
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
    LOG_DEBUG("client_conn_timeout_cb: STAT_CONCURRENT_CONNECTIONS decremented (timeout). Current: %lu", g_concurrent_connections);
    client_conn_cleanup(EV_A_ conn_data);
    // Cycle to the next server port for the next attempt
    g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;
    LOG_DEBUG("Timeout, trying next server port: %d", g_server_ports[g_current_server_port_index]);
    // Check if we still need to create a connection based on the objective
    perf_config_t *config = conn_data->config;
    if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
        g_concurrent_connections < g_current_target_connections) {
        create_tcp_connection(g_main_loop, config);
    } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0 &&
               scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
        create_tcp_connection(g_main_loop, config);
    }
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
    TAILQ_INIT(&g_client_conn_pool_list);

    // Preallocate client_conn_data pool with reduced size to prevent memory issues in containers
    const int REDUCED_POOL_SIZE = 1000; // Reduced from 8000 to conserve memory
    g_client_conn_pool = (struct client_conn_data *)calloc(REDUCED_POOL_SIZE, sizeof(struct client_conn_data));
    if (!g_client_conn_pool) {
        LOG_ERROR("Failed to allocate memory for client connection pool. Out of memory or container memory limits reached.");
        return;
    }

    for (int i = 0; i < REDUCED_POOL_SIZE; i++) {
        TAILQ_INSERT_TAIL(&g_client_conn_pool_list, &g_client_conn_pool[i], entries);
    }
    g_client_conn_pool_used = 0;
    LOG_INFO("Preallocated %d client connection structures (reduced to conserve memory).", REDUCED_POOL_SIZE);

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
                g_current_target_connections = (int)(config->objective.value * progress + 0.99); // Round up to ensure at least 1 connection early
                if (g_current_target_connections < 1 && config->objective.value > 0) {
                    g_current_target_connections = 1; // Ensure at least 1 connection if objective is set
                }
                LOG_DEBUG("RAMP_UP: Progress %.2f, Target Connections: %d", progress, g_current_target_connections);
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

            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = (int)(config->objective.value * (1.0 - progress));
                // Logic to close connections if current > target
                while (g_concurrent_connections > g_current_target_connections && !TAILQ_EMPTY(&g_tcp_conn_list)) {
                    struct client_conn_data *conn_to_close = TAILQ_FIRST(&g_tcp_conn_list);
                    LOG_INFO("Closing TCP connection during RAMP_DOWN. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
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
        if (g_local_port_used > g_current_target_connections && g_current_target_connections > 0) {
            LOG_WARN("High local port usage: %d ports in use, exceeding target concurrent connections %d.", g_local_port_used, g_current_target_connections);
        } else {
            LOG_DEBUG("Local port usage: %d out of %d ports in use.", g_local_port_used, g_local_port_count);
        }
        metrics_update_port_usage(g_local_port_used, g_local_port_count);
        g_last_port_stats_log_time = current_time;
    }
    if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
        if (g_concurrent_connections < g_current_target_connections) {
            LOG_DEBUG("Creating connections to reach target. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
            int connections_to_create = g_current_target_connections - g_concurrent_connections;
            // Create multiple connections to close the gap faster, but limit to a reasonable batch size
            int batch_size = connections_to_create > 10 ? 10 : connections_to_create;
            for (int i = 0; i < batch_size; i++) {
                if (g_concurrent_connections >= g_current_target_connections) {
                    break;
                }
                create_tcp_connection(EV_A_ config);
            }
        }
    } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
        if (scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
            LOG_DEBUG("Creating connections to reach total target. Opened: %lu, Target: %d", scheduler_get_stats()->connections_opened, g_current_target_total_connections);
            create_tcp_connection(EV_A_ config);
        }
    }
}

static void create_tcp_connection(struct ev_loop *loop, perf_config_t *config) {
    // Check if we've reached the maximum concurrent connections or memory limits
    if (g_concurrent_connections >= g_current_target_connections && g_current_target_connections > 0) {
        LOG_DEBUG("Maximum concurrent connections reached (%d). Skipping new connection creation.", g_current_target_connections);
        return;
    }
    // Additional check for pool usage to prevent excessive memory allocation
    if (g_client_conn_pool_used >= CLIENT_CONN_POOL_SIZE) {
        LOG_WARN("Client connection pool exhausted (%d used). Cannot create more connections due to memory constraints.", g_client_conn_pool_used);
        return;
    }
    struct client_conn_data *conn_data = NULL;
    if (!TAILQ_EMPTY(&g_client_conn_pool_list)) {
        conn_data = TAILQ_FIRST(&g_client_conn_pool_list);
        TAILQ_REMOVE(&g_client_conn_pool_list, conn_data, entries);
        g_client_conn_pool_used++;
        memset(conn_data, 0, sizeof(struct client_conn_data));
        LOG_DEBUG("create_tcp_connection: Reusing client_conn_data from pool at %p. Used: %d/%d", conn_data, g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
    } else {
        LOG_WARN("create_tcp_connection: No available client_conn_data in pool, allocating new. Used: %d/%d", g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
        conn_data = (struct client_conn_data *)malloc(sizeof(struct client_conn_data));
        if (!conn_data) {
            LOG_ERROR("create_tcp_connection: Failed to allocate memory for client connection data.");
            return;
        }
        memset(conn_data, 0, sizeof(struct client_conn_data));
        LOG_DEBUG("create_tcp_connection: Allocated new client_conn_data at %p", conn_data);
    }

    conn_data->config = config;
    conn_data->total_received = 0;
    conn_data->data_received = 0;
    conn_data->header_length = 0;
    conn_data->content_length = 0;
    conn_data->local_port = get_local_port();
    if (conn_data->local_port == -1) {
        LOG_ERROR("No available local ports for new connection.");
        if (conn_data >= g_client_conn_pool && conn_data < g_client_conn_pool + CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
            LOG_DEBUG("Returned client_conn_data to pool due to no available ports. Used: %d/%d", g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
        } else {
            free(conn_data);
        }
        return;
    }
    ev_timer_init(&conn_data->request_timer, client_request_timer_cb, 0., 0.);
    conn_data->request_timer.data = conn_data;
    conn_data->requests_sent_on_connection = 0;

    ev_timer_init(&conn_data->conn_timeout_timer, client_conn_timeout_cb, 10., 0.);
    conn_data->conn_timeout_timer.data = conn_data;
    ev_timer_start(g_main_loop, &conn_data->conn_timeout_timer);

    const char *request_path = config->http_config.client_request_path;
    conn_data->send_buffer_size = snprintf(NULL, 0, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);
    conn_data->send_buffer = (char *)malloc(conn_data->send_buffer_size + 1);
    if (!conn_data->send_buffer) {
        LOG_ERROR("create_tcp_connection: Failed to allocate memory for client send buffer for conn_data %p.", conn_data);
        if (conn_data >= g_client_conn_pool && conn_data < g_client_conn_pool + CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
            LOG_DEBUG("create_tcp_connection: Returned client_conn_data to pool due to send buffer allocation failure. Used: %d/%d", g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
        } else {
            free(conn_data);
        }
        return;
    }
    snprintf(conn_data->send_buffer, conn_data->send_buffer_size + 1, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);
    LOG_DEBUG("create_tcp_connection: Allocated send_buffer at %p for conn_data %p", conn_data->send_buffer, conn_data);

    conn_data->recv_buffer_size = sizeof(conn_data->recv_buffer); // 2K buffer for receiving data
    // recv_buffer is a fixed-size array within client_conn_data, no need to allocate

    conn_data->nh.proto = PROTO_TCP;
    conn_data->nh.type = SOCK_STREAM;
    conn_data->nh.is_ipv4 = 1;

    if (netbsd_socket(&conn_data->nh) != 0) {
        LOG_ERROR("Failed to create client socket for connection data %p: %s (errno: %d)", conn_data, strerror(errno), errno);
        metrics_inc_failure();
        free(conn_data->send_buffer);
        if (conn_data >= g_client_conn_pool && conn_data < g_client_conn_pool + CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
            LOG_DEBUG("Returned client_conn_data %p to pool after socket failure. Used: %d/%d", conn_data, g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
        } else {
            LOG_DEBUG("Freeing client_conn_data %p not from pool after socket failure", conn_data);
            free(conn_data);
        }
        return_local_port(conn_data->local_port);
        // Prevent excessive retries if we're failing repeatedly
        static int consecutive_socket_failures = 0;
        consecutive_socket_failures++;
        if (consecutive_socket_failures > 10) {
            LOG_ERROR("Too many consecutive socket creation failures (%d). Pausing connection attempts.", consecutive_socket_failures);
            return;
        }
        // Reset counter if we have a successful connection later
        return;
    }
    // Reset counter on success
    static int consecutive_socket_failures = 0;
    consecutive_socket_failures = 0;
    LOG_DEBUG("Created socket for connection data %p with handle %p and socket pointer %p", conn_data, &conn_data->nh, conn_data->nh.so);

    int optval = 1;
    if (netbsd_reuseaddr(&conn_data->nh, &optval, sizeof(optval))) {
        LOG_ERROR("Set reuseaddr option failed.");
        netbsd_close(&conn_data->nh);
        free(conn_data->send_buffer);
        if (g_client_conn_pool_used < CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
        } else {
            free(conn_data);
        }
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
        return_local_port(conn_data->local_port);
        netbsd_close(&conn_data->nh);
        free(conn_data->send_buffer);
        if (g_client_conn_pool_used < CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
        } else {
            free(conn_data);
        }
        return;
    }
    LOG_DEBUG("Bound to local port %d", conn_data->local_port);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    int server_port = g_server_ports[g_current_server_port_index];
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    // Non-blocking connect
    int ret = netbsd_connect(&conn_data->nh, (struct sockaddr *)&server_addr);
    if (ret != 0 && ret != EINPROGRESS) {
        LOG_ERROR("Failed to connect from: %d to %s:%d: %d:%s", conn_data->local_port,
                  config->network.dst_ip_start, server_port, ret, strerror(ret));
        metrics_inc_failure();
        return_local_port(conn_data->local_port);
        netbsd_close(&conn_data->nh);
        //free(conn_data->recv_buffer);
        free(conn_data->send_buffer);
        if (g_client_conn_pool_used < CLIENT_CONN_POOL_SIZE) {
            TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
            g_client_conn_pool_used--;
        } else {
            free(conn_data);
        }
        // Cycle to the next server port for the next attempt
        g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;
        LOG_DEBUG("Immediate connection failure, trying next server port: %d", g_server_ports[g_current_server_port_index]);
        // Check if we still need to create a connection based on the objective
        if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
            g_concurrent_connections < g_current_target_connections) {
            create_tcp_connection(g_main_loop, config);
        } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0 &&
                   scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
            create_tcp_connection(g_main_loop, config);
        }
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

    conn_data->recv_buffer_size = sizeof(conn_data->recv_buffer); // 2K buffer for receiving data
    // recv_buffer is a fixed-size array within client_conn_data, no need to allocate

    conn_data->nh.proto = PROTO_UDP;
    conn_data->nh.type = SOCK_DGRAM;
    conn_data->nh.is_ipv4 = 1;

    if (netbsd_socket(&conn_data->nh) != 0) {
        LOG_ERROR("Failed to create UDP client socket: %s", strerror(errno));
        //free(conn_data->recv_buffer);
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
        free(conn_data->send_buffer);
        free(conn_data);
    }
}

static void client_conn_cleanup(struct ev_loop *loop, struct client_conn_data *conn_data) {
    if (!conn_data || conn_data->cleaning_up) {
        LOG_DEBUG("client_conn_cleanup: Already cleaning up or invalid conn_data at %p.", conn_data);
        return;
    }
    conn_data->cleaning_up = 1;

    LOG_DEBUG("client_conn_cleanup: Starting cleanup for connection data at %p", conn_data);
    if (conn_data->nh.proto == PROTO_TCP) {
        if (conn_data->is_connected) {
            TAILQ_REMOVE(&g_tcp_conn_list, conn_data, entries);
            scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
            LOG_DEBUG("client_conn_cleanup: STAT_CONCURRENT_CONNECTIONS decremented (cleanup). Current: %lu", g_concurrent_connections);
        }
        scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
    }
    LOG_DEBUG("client_conn_cleanup: Closing netbsd handle at %p with socket %p for conn_data %p", &conn_data->nh, conn_data->nh.so, conn_data);
    // Clear callbacks to prevent further events
    conn_data->nh.read_cb = NULL;
    conn_data->nh.write_cb = NULL;
    conn_data->nh.close_cb = NULL;
    netbsd_close(&conn_data->nh);
    conn_data->nh.so = NULL; // Ensure the socket pointer is cleared
    ev_timer_stop(g_main_loop, &conn_data->request_timer);
    ev_timer_stop(g_main_loop, &conn_data->conn_timeout_timer);
    // Free resources
    if (conn_data->send_buffer) {
        LOG_DEBUG("client_conn_cleanup: Freeing send_buffer at %p for conn_data %p", conn_data->send_buffer, conn_data);
        free(conn_data->send_buffer);
        conn_data->send_buffer = NULL;
    }
    return_local_port(conn_data->local_port);
    LOG_DEBUG("client_conn_cleanup: Returned local port %d to pool for conn_data %p", conn_data->local_port, conn_data);
    // Return conn_data to pool if within pool bounds
    if (conn_data >= g_client_conn_pool && conn_data < g_client_conn_pool + CLIENT_CONN_POOL_SIZE) {
        TAILQ_INSERT_TAIL(&g_client_conn_pool_list, conn_data, entries);
        g_client_conn_pool_used--;
        LOG_DEBUG("client_conn_cleanup: Returned client_conn_data to pool at %p. Used: %d/%d", conn_data, g_client_conn_pool_used, CLIENT_CONN_POOL_SIZE);
    } else {
        LOG_DEBUG("client_conn_cleanup: Freeing client_conn_data not from pool at %p", conn_data);
        free(conn_data);
    }
    LOG_DEBUG("client_conn_cleanup: Cleanup complete for connection data at %p", conn_data);
}

static void client_conn_connect_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    perf_config_t *config = conn_data->config;
    LOG_INFO("client_conn_connect_cb: Entry. nh: %p, so: %p, local_port: %d", 
              nh, nh->so, conn_data->local_port);

    int socket_err = netbsd_socket_error(nh);
    if (socket_err == 0) {
        LOG_INFO("Successfully connected to %s:%d from local port %d", 
                 config->network.dst_ip_start, config->network.dst_port_start, conn_data->local_port);
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
        LOG_ERROR("Failed to connect to %s:%d from local port %d: %s (error code: %d)",
                  config->network.dst_ip_start, config->network.dst_port_start, conn_data->local_port, strerror(socket_err), socket_err);
        metrics_inc_failure();
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1); // Decrement for failed connection
        LOG_DEBUG("client_conn_connect_cb: STAT_CONCURRENT_CONNECTIONS decremented (failed connect). Current: %lu", g_concurrent_connections);
        client_conn_cleanup(g_main_loop, conn_data);
        // Cycle to the next server port for the next attempt
        g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;
        LOG_DEBUG("Retrying with next server port: %d", g_server_ports[g_current_server_port_index]);
        // Try to create another connection if objective is TCP_CONCURRENT or HTTP_REQUESTS and still below target
        if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
            g_concurrent_connections < g_current_target_connections) {
            create_tcp_connection(g_main_loop, config);
        } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0 &&
                   scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
            create_tcp_connection(g_main_loop, config);
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
        LOG_INFO("Reached requests_per_connection limit (%d). Not sending more requests.",
                 config->objective.requests_per_connection);
        return; 
    }
    if (conn_data->sent_size < conn_data->send_buffer_size) { // Only send if we haven't sent the full request yet
        if (conn_data->sent_size == 0) { // First part of a new request
            conn_data->request_send_time = ev_now(g_main_loop);
        }
    } else {
        LOG_DEBUG("Full request already sent, waiting for response.");
        return; // Do not send another request until the response for the current one is fully received
    }

    struct iovec iov;
    iov.iov_base = conn_data->send_buffer + conn_data->sent_size;
    size_t remaining = conn_data->send_buffer_size - conn_data->sent_size;
    const size_t MAX_BLOCK_SIZE = 2 * 1024 * 1024; // 2MB
    iov.iov_len = (remaining > MAX_BLOCK_SIZE) ? MAX_BLOCK_SIZE : remaining;
    
    ssize_t bytes_written = netbsd_write(nh, &iov, 1);

    if (bytes_written > 0) {
        conn_data->sent_size += bytes_written;
        scheduler_inc_stat(STAT_BYTES_SENT, bytes_written);
        LOG_INFO("client_conn_write_cb: Sent %zd bytes (total %zu/%zu).", bytes_written, conn_data->sent_size, conn_data->send_buffer_size);

        if (conn_data->sent_size >= conn_data->send_buffer_size) {
            LOG_INFO("client_conn_write_cb: Full request sent.");
            scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
            conn_data->sent_size = conn_data->send_buffer_size; // Do not reset to 0, keep it at max to prevent re-sending until response is received
            // After writing, we expect a read event.
            // The read callback is already set, so we just wait.
        } else {
            LOG_DEBUG("client_conn_write_cb: Partial write, waiting for next writable event.");
            // Not fully sent, so we need to be called again.
            // The event loop will trigger us again when the socket is writable.
        }
    } else if (bytes_written < 0) {
        if (bytes_written != -EPIPE && bytes_written != -EAGAIN && bytes_written != -EWOULDBLOCK) {
            LOG_INFO("client_conn_write_cb: Failed to write to socket: %s (errno: %d, bytes_written: %zd)", strerror(errno), errno, bytes_written);
            metrics_inc_failure();
            LOG_DEBUG("client_conn_write_cb: Write failed, calling cleanup.");
            client_conn_cleanup(g_main_loop, conn_data);
            // Only create a new connection if we are below target for TCP_CONCURRENT or HTTP_REQUESTS
            if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
                g_concurrent_connections < g_current_target_connections) {
                LOG_INFO("Creating new connection after write failure. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
                create_tcp_connection(g_main_loop, config);
            }
        } else if (bytes_written == -EAGAIN || bytes_written == -EWOULDBLOCK) {
            LOG_DEBUG("client_conn_write_cb: EAGAIN/EWOULDBLOCK during write, will retry.");
        }
    } else { // bytes_written == 0
        LOG_INFO("Zero bytes written, but data was available. Data length: %zu", iov.iov_len);
    }
    LOG_DEBUG("client_conn_write_cb: Exit.");
}

static void process_http_response(struct client_conn_data *conn_data) {
    perf_config_t *config = conn_data->config;

    if (conn_data->total_received == 0) {
        return; // No data to process yet
    }

    // Only parse headers if we haven't done so yet
    if (conn_data->header_length == 0) {
        int pret, minor_version, status;
        const char *msg;
        size_t msg_len;
        struct phr_header headers[100];
        size_t num_headers = sizeof(headers) / sizeof(headers[0]);
        pret = phr_parse_response(conn_data->recv_buffer, conn_data->data_received, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

        if (pret > 0) { // successful parse of headers
            LOG_INFO("HTTP Response: %d %.*s", status, (int)msg_len, msg);
            conn_data->header_length = pret;

            // Record latency once headers are received
            double response_recv_time = ev_now(g_main_loop);
            uint64_t latency_ms = (uint64_t)((response_recv_time - conn_data->request_send_time) * 1000);
            metrics_add_latency(latency_ms);
            metrics_inc_success(); // Increment success for a completed request-response cycle
            scheduler_inc_stat(STAT_RESPONSES_RECEIVED, 1);

            // Extract Content-Length from headers if available
            conn_data->content_length = 0;
            for (size_t i = 0; i < num_headers; i++) {
                if (strncasecmp(headers[i].name, "Content-Length", headers[i].name_len) == 0) {
                    char length_str[32];
                    size_t len = headers[i].value_len < sizeof(length_str) - 1 ? headers[i].value_len : sizeof(length_str) - 1;
                    strncpy(length_str, headers[i].value, len);
                    length_str[len] = '\0';
                    conn_data->content_length = atoll(length_str);
                    break;
                }
            }

            LOG_INFO("Parsed Content-Length: %lld", conn_data->content_length);
            conn_data->data_received = 0; // reset receive buffer
            // Check if we've received all content
            size_t content_received = conn_data->total_received - conn_data->header_length;
            if (content_received >= (size_t)conn_data->content_length) {
                // Log only the content length as per Content-Length header
                size_t reported_content_received = content_received > (size_t)conn_data->content_length ? (size_t)conn_data->content_length : content_received;
                LOG_INFO("All content received: %zu bytes: requests_sent_on_connection: %d", reported_content_received, conn_data->requests_sent_on_connection);
                if (config->objective.requests_per_connection > 0 &&
                    conn_data->requests_sent_on_connection >= config->objective.requests_per_connection) {
                    LOG_INFO("client_conn_read_cb: Reached requests_per_connection limit (%d). Closing connection.",
                             config->objective.requests_per_connection);
                    client_conn_cleanup(g_main_loop, conn_data);
                    // Create a new connection to maintain concurrency if in RAMP_UP or SUSTAIN phase
                    test_phase_t current_phase = scheduler_get_current_phase();
                    if ((strcmp(config->objective.type, "HTTP_REQUESTS") == 0 || strcmp(config->objective.type, "TCP_CONCURRENT") == 0) &&
                        (current_phase == PHASE_RAMP_UP || current_phase == PHASE_SUSTAIN) &&
                        g_concurrent_connections < g_current_target_connections) {
                        LOG_INFO("Creating new connection to maintain concurrency after reaching request limit. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
                        create_tcp_connection(g_main_loop, config);
                    }
                } else if (strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                    // Reset for next request and immediately send another one
                    conn_data->sent_size = 0; // Reset to allow sending a new request
                    conn_data->total_received = 0;
                    conn_data->data_received = 0;
                    conn_data->header_length = 0;
                    conn_data->content_length = 0;
                    conn_data->requests_sent_on_connection++; // Increment after receiving full response
                    LOG_INFO("Sending request #%d on this connection", conn_data->requests_sent_on_connection);
                    client_conn_write_cb(&conn_data->nh, 0);
                }
            }
            /*else*/ {
                LOG_INFO("Waiting for more content: received %zu of %lld bytes", content_received, conn_data->content_length);
                conn_data->data_received = 0;
                // Ensure we continue reading by not returning prematurely
                // Calculate the content length received, drain all of them, let the receive buffer offset to 0, for next netbsd_read
                if (conn_data->total_received > 0 && content_received > 0) {
                    // If we have received some content, but not all, we can optimize by shifting data
                    // to make room for more data in the buffer if needed. But for simplicity,
                    // we'll keep all data until the full content is received.
                    LOG_DEBUG("Partial content received, waiting for more data.");
                }
            }
        } else if (pret == -1) { // parse error
            LOG_INFO("HTTP parse error in response: %d:%s", pret, conn_data->recv_buffer);
            metrics_inc_failure();
            client_conn_cleanup(g_main_loop, conn_data);
        } else { // incomplete response headers
            LOG_DEBUG("Incomplete HTTP response headers, waiting for more data");
            // Keep the connection open to receive more data
        }
    } else {
        // Headers already parsed, just check if all content is received
        size_t content_received = conn_data->total_received - conn_data->header_length;
        conn_data->data_received = 0; // reset the receive buffer
        if (content_received >= (size_t)conn_data->content_length) {
            // Log only the content length as per Content-Length header
            size_t reported_content_received = content_received > (size_t)conn_data->content_length ? (size_t)conn_data->content_length : content_received;
            LOG_INFO("All content received: %zu bytes, requests_sent_on_connection: %d", reported_content_received, conn_data->requests_sent_on_connection);
            conn_data->requests_sent_on_connection++; // Increment after receiving full response
            if (config->objective.requests_per_connection > 0 &&
                conn_data->requests_sent_on_connection >= config->objective.requests_per_connection) {
                LOG_INFO("client_conn_read_cb: Reached requests_per_connection limit (%d). Closing connection.",
                         config->objective.requests_per_connection);
                client_conn_cleanup(g_main_loop, conn_data);
                // Create a new connection to maintain concurrency if in RAMP_UP or SUSTAIN phase
                test_phase_t current_phase = scheduler_get_current_phase();
                if ((strcmp(config->objective.type, "HTTP_REQUESTS") == 0 || strcmp(config->objective.type, "TCP_CONCURRENT") == 0) &&
                    (current_phase == PHASE_RAMP_UP || current_phase == PHASE_SUSTAIN) &&
                    g_concurrent_connections < g_current_target_connections) {
                    LOG_INFO("Creating new connection to maintain concurrency after reaching request limit. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
                    create_tcp_connection(g_main_loop, config);
                }
            } else if (strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                // Reset for next request and immediately send another one
                conn_data->sent_size = 0; // Reset to allow sending a new request
                conn_data->total_received = 0;
                conn_data->data_received = 0;
                conn_data->header_length = 0;
                conn_data->content_length = 0;
                LOG_INFO("Sending request #%d on this connection", conn_data->requests_sent_on_connection);
                client_conn_write_cb(&conn_data->nh, 0);
            }
        } else {
            LOG_INFO("Waiting for more content: received %zu of %lld bytes", content_received, conn_data->content_length);
            // Ensure we continue reading by not returning prematurely
        }
    }
}

static void client_conn_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    LOG_INFO("client_conn_read_cb: Entry. nh: %p, so: %p", nh, nh->so);
    if (!conn_data || conn_data->cleaning_up) {
        return; // Connection is being cleaned up
    }

    perf_config_t *config = conn_data->config;

    if (nh->proto == PROTO_UDP) {
        struct iovec iov;
        iov.iov_base = conn_data->recv_buffer;
        iov.iov_len = conn_data->recv_buffer_size;
        struct sockaddr_in server_addr;
        ssize_t bytes_read = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&server_addr);

        if (bytes_read > 0) {
            LOG_INFO("client_conn_read_cb: Received %zd bytes (UDP).", bytes_read);
            scheduler_inc_stat(STAT_BYTES_RECEIVED, bytes_read);
            double response_recv_time = ev_now(g_main_loop);
            uint64_t latency_ms = (uint64_t)((response_recv_time - conn_data->request_send_time) * 1000);
            metrics_add_latency(latency_ms);
            metrics_inc_success();
            scheduler_inc_stat(STAT_RESPONSES_RECEIVED, 1);
            client_conn_cleanup(g_main_loop, conn_data);
        } else if (bytes_read == 0) {
            LOG_INFO("client_conn_read_cb: Server closed connection (UDP).");
            ev_timer_stop(g_main_loop, &conn_data->request_timer);
            client_conn_cleanup(g_main_loop, conn_data);
        } else {
            if (bytes_read != -EPIPE) {
                metrics_inc_failure();
            }
            LOG_DEBUG("client_conn_read_cb: Calling cleanup on read error (UDP).");
            ev_timer_stop(g_main_loop, &conn_data->request_timer);
            client_conn_cleanup(g_main_loop, conn_data);
        }
        LOG_DEBUG("client_conn_read_cb: Exit (UDP).");
        return;
    }
    int i = 0;
    // For TCP, read all available data until EWOULDBLOCK or error
    while (i == 0) {
        struct iovec iov;
        iov.iov_base = conn_data->recv_buffer + conn_data->data_received;
        iov.iov_len = conn_data->recv_buffer_size - conn_data->data_received;

        LOG_INFO("client_conn_read_cb: nh: %p, start read  %zd bytes (TCP).", nh, iov.iov_len);
        if (iov.iov_len == 0) {
            break;
            printf("CCB: ********ERROR|\n");
        }
        ssize_t bytes_read = netbsd_read(nh, &iov, 1);
        if (bytes_read > 0) {
            LOG_INFO("client_conn_read_cb: Received %zd bytes (TCP).", bytes_read);
            scheduler_inc_stat(STAT_BYTES_RECEIVED, bytes_read);
            conn_data->total_received += bytes_read;
            conn_data->data_received += bytes_read;

            // Check if we need to resize the receive buffer
#if 0
            if (conn_data->data_received >= conn_data->recv_buffer_size) {
                size_t new_size = conn_data->recv_buffer_size * 2; // Double the current size
                char *new_buffer = (char *)realloc(conn_data->recv_buffer, new_size);
                if (new_buffer) {
                    conn_data->recv_buffer = new_buffer;
                    conn_data->recv_buffer_size = new_size;
                    LOG_INFO("Resized receive buffer to %zu bytes", new_size);
                } else {
                    LOG_ERROR("Failed to resize receive buffer");
                    metrics_inc_failure();
                    client_conn_cleanup(g_main_loop, conn_data);
                    break;
                }
            }
#endif
            process_http_response(conn_data);
        } else if (bytes_read == 0 || bytes_read == -22 /*invalid*/) {
            /*
            LOG_WARN("client_conn_read_cb: Server closed connection (TCP).");
            ev_timer_stop(g_main_loop, &conn_data->request_timer);
            client_conn_cleanup(g_main_loop, conn_data);
            if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
                g_concurrent_connections < g_current_target_connections) {
                LOG_INFO("Creating new connection after server close. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
                create_tcp_connection(g_main_loop, config);
            }
            */
            break;
        } else {
            if (bytes_read == -35/*EAGAIN, EWOULDBLOCK*/) {
                LOG_DEBUG("client_conn_read_cb: EWOULDBLOCK, waiting for more data.");
                break; // Wait for the next read event
            } else {
                if (bytes_read != -32/*-EPIPE*/ || bytes_read != -54/*ECONNRESET*/) {
                    metrics_inc_failure();
                }
                LOG_INFO("client_conn_read_cb: Read error (TCP). bytes_read: %zd, errno: %d", bytes_read, errno);
                ev_timer_stop(g_main_loop, &conn_data->request_timer);
                client_conn_cleanup(g_main_loop, conn_data);
                if ((strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) &&
                    g_concurrent_connections < g_current_target_connections) {
                    LOG_INFO("Creating new connection after read error. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
                    create_tcp_connection(g_main_loop, config);
                }
                break;
            }
        }
    }

    // Process the received data if any
    //if (nh->proto == PROTO_TCP && conn_data->total_received > 0) {
        //process_http_response(conn_data);
    //}

    LOG_DEBUG("client_conn_read_cb: Exit (TCP).");
}

static void client_conn_close_cb(void *handle, int events) {
    LOG_DEBUG("client_conn_close_cb: Entry point for handle %p", handle);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct client_conn_data *conn_data = (struct client_conn_data *)nh->data;
    LOG_INFO("Client connection closed for socket %p", nh->so);

    if (!conn_data) {
        LOG_WARN("client_conn_close_cb: conn_data is NULL, nothing to cleanup.");
        return;
    }

    test_phase_t current_phase = scheduler_get_current_phase();

    // Try to create another connection if objective is TCP_CONCURRENT or HTTP_REQUESTS and we are in RAMP_UP or SUSTAIN phase
    if ((strcmp(conn_data->config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(conn_data->config->objective.type, "HTTP_REQUESTS") == 0) &&
        (current_phase == PHASE_RAMP_UP || current_phase == PHASE_SUSTAIN) &&
        g_concurrent_connections < g_current_target_connections) {
        LOG_INFO("Creating new connection to maintain concurrency after close. Current: %lu, Target: %d", g_concurrent_connections, g_current_target_connections);
        create_tcp_connection(g_main_loop, conn_data->config);
    } else if (strcmp(conn_data->config->objective.type, "TOTAL_CONNECTIONS") == 0 &&
               scheduler_get_stats()->connections_opened < g_current_target_total_connections) {
        LOG_INFO("Creating new connection to reach total connections target. Opened: %lu, Target: %d", scheduler_get_stats()->connections_opened, g_current_target_total_connections);
        create_tcp_connection(g_main_loop, conn_data->config);
    }

    // Call the cleanup function to handle resource freeing and pool management
    client_conn_cleanup(g_main_loop, conn_data);
    LOG_DEBUG("client_conn_close_cb: Exit for handle %p", handle);
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
    // Limit port usage to the maximum concurrent connections defined in config
    if (g_local_port_used >= g_current_target_connections && g_current_target_connections > 0) {
        LOG_WARN("Reached max concurrent port limit based on target connections (%d). Cannot allocate more ports.", g_current_target_connections);
        return -1;
    }
    if (g_local_port_used >= g_local_port_count) {
        LOG_WARN("No more local ports available in pool, reusing ports.");
        // Reset the index to allow reuse of ports
        g_current_port_index = 0;
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
