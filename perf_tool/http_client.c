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
#include "tcp_layer.h"
#include "deps/picohttpparser/picohttpparser.h"

#define MAX_RECV_SIZE 2048
extern struct ev_loop *g_main_loop;


typedef struct http_conn {
    tcp_conn_t *tcp_conn;
    perf_config_t *config;
    char *send_buffer;
    size_t send_buffer_size;
    size_t sent_size;
    char recv_buffer[MAX_RECV_SIZE];
    size_t recv_buffer_size;
    size_t total_received;
    size_t data_received;
    size_t header_length;
    long long content_length;
    double request_send_time;
    int requests_sent_on_connection;
    TAILQ_ENTRY(http_conn) entries;
} http_conn_t;

TAILQ_HEAD(http_conn_list_head, http_conn);
static struct http_conn_list_head g_http_conn_list;

static void http_on_connect(struct tcp_conn *conn, int status);
static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len);
static void http_on_write(struct tcp_conn *conn);
static void http_on_close(struct tcp_conn *conn);

static tcp_callbacks_t http_callbacks = {
    .on_connect = http_on_connect,
    .on_read = http_on_read,
    .on_write = http_on_write,
    .on_close = http_on_close,
};

void http_client_init(perf_config_t *config) {
    TAILQ_INIT(&g_http_conn_list);
    tcp_layer_init_local_port_pool(config);
}

void create_http_connection(struct ev_loop *loop, perf_config_t *config) {
    static int counter = 0;
    if (counter++ > 10) return;
    http_conn_t *http_conn = (http_conn_t *)malloc(sizeof(http_conn_t));
    memset(http_conn, 0, sizeof(http_conn_t));
    http_conn->config = config;
    http_conn->recv_buffer_size = MAX_RECV_SIZE;

    const char *request_path = config->http_config.client_request_path;
    http_conn->send_buffer_size = snprintf(NULL, 0, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);
    http_conn->send_buffer = (char *)malloc(http_conn->send_buffer_size + 1);
    snprintf(http_conn->send_buffer, http_conn->send_buffer_size + 1, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", request_path, config->network.dst_ip_start);
    LOG_DEBUG("HTTP layer calling TCP layer to connect to %s:%d from local port %d",
              config->network.dst_ip_start, config->network.dst_port_start, 0);
    if (tcp_layer_connect(loop, config, 0, &http_callbacks, http_conn, &http_conn->tcp_conn) != 0) {
        LOG_ERROR("Failed to create TCP connection.");
        free(http_conn->send_buffer);
        free(http_conn);
        //tcp_layer_return_local_port(local_port);
    }
    
    TAILQ_INSERT_TAIL(&g_http_conn_list, http_conn, entries);
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, 1);
}

static void http_on_connect(struct tcp_conn *conn, int status) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    LOG_DEBUG("HTTP layer received connect callback from TCP layer. Status: %d", status);
    if (status == 0) {
        LOG_INFO("HTTP connection established.");
        scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
        scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
        metrics_inc_success();
        http_conn->request_send_time = ev_now(g_main_loop);
        LOG_INFO("HTTP write data: %s.", http_conn->send_buffer);
        tcp_layer_write(conn, http_conn->send_buffer, http_conn->send_buffer_size);
    } else {
        LOG_ERROR("HTTP connection failed to connect.");
        metrics_inc_failure();
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        // No need to call tcp_layer_close as it's already being closed by TCP layer
        free(http_conn->send_buffer);
        free(http_conn);
    }
}

static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    
    if (len > 0) {
        http_conn->total_received += len;
        LOG_DEBUG("HTTP read: %d:%s", len, data);

        // Only copy data to buffer if we haven't parsed the headers yet
        if (http_conn->header_length == 0) {
            if (http_conn->data_received + len > http_conn->recv_buffer_size) {
                // Buffer overflow
                return;
            }
            memcpy(http_conn->recv_buffer + http_conn->data_received, data, len);
            http_conn->data_received += len;
        }

        // Process response
        if (http_conn->header_length == 0) {
            int pret, minor_version, status;
            const char *msg;
            size_t msg_len;
            struct phr_header headers[100];
            size_t num_headers = sizeof(headers) / sizeof(headers[0]);
            pret = phr_parse_response(http_conn->recv_buffer, http_conn->data_received, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

            if (pret > 0) {
                http_conn->header_length = pret;
                double response_recv_time = ev_now(g_main_loop);
                uint64_t latency_ms = (uint64_t)((response_recv_time - http_conn->request_send_time) * 1000);
                metrics_add_latency(latency_ms);
                metrics_inc_success();
                scheduler_inc_stat(STAT_RESPONSES_RECEIVED, 1);

                // Get content length
                for (size_t i = 0; i < num_headers; i++) {
                    if (strncasecmp(headers[i].name, "Content-Length", headers[i].name_len) == 0) {
                        char length_str[32];
                        size_t clen = headers[i].value_len < sizeof(length_str) - 1 ? headers[i].value_len : sizeof(length_str) - 1;
                        strncpy(length_str, headers[i].value, clen);
                        length_str[clen] = '\0';
                        http_conn->content_length = atoll(length_str);
                        break;
                    }
                }
            }
        }

        if (http_conn->header_length > 0) {
            size_t content_received = http_conn->total_received - http_conn->header_length;
            LOG_DEBUG("http body content_received :%d", content_received);
            if (content_received >= (size_t)http_conn->content_length) {
                // Full response received
                http_conn->requests_sent_on_connection++;
                if (http_conn->config->objective.requests_per_connection > 0 &&
                    http_conn->requests_sent_on_connection >= http_conn->config->objective.requests_per_connection) {
                    LOG_DEBUG("http read all body, close the tcp");
                    tcp_layer_close(conn);
                } else {
                    // Send another request
                    http_conn->sent_size = 0;
                    http_conn->total_received = 0;
                    http_conn->data_received = 0;
                    http_conn->header_length = 0;
                    http_conn->content_length = 0;
                    http_conn->request_send_time = ev_now(g_main_loop);
                    tcp_layer_write(conn, http_conn->send_buffer, http_conn->send_buffer_size);
                }
            } else {
                LOG_DEBUG("http read body len: %d", content_received);
            }
        }
    }
}

static void http_on_write(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    http_conn->sent_size = http_conn->send_buffer_size;
    // Data has been written, we can send more if needed.
    // In this simple case, we send the whole request at once.
}

static void http_on_close(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    LOG_DEBUG("http_on_close on client");
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
    scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
    TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
    //tcp_layer_return_local_port(http_conn->tcp_conn->local_port);
    // No need to call tcp_layer_close here as it's already closing
    free(http_conn->send_buffer);
    free(http_conn);
}

void http_client_close_excess_connections(int excess) {
    http_conn_t *http_conn;
    int closed = 0;
    
    while ((http_conn = TAILQ_FIRST(&g_http_conn_list)) != NULL && closed < excess) {
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        // Temporarily set on_close to NULL to prevent callback during active close
        http_conn->tcp_conn->callbacks.on_close = NULL;
        tcp_layer_close(http_conn->tcp_conn);
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
        scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
        closed++;
    }
}
