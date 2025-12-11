#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <ev.h>
#include <u_socket.h>

#include "client.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"
#include "tcp_layer.h"
#include "ssl_layer.h"
#include "common.h"
#include "deps/picohttpparser/picohttpparser.h"
#include <stdbool.h>

#define MAX_RECV_SIZE 1024*10
#define MAX_STALLED_TO_CLOSE_PER_TICK 10

extern struct ev_loop *g_main_loop;

typedef struct {
    char *request;
    size_t request_size;
} path_request_data_t;

static path_request_data_t *g_path_requests = NULL;
static int g_path_requests_count = 0;
static int g_next_path_index = 0;

typedef struct http_conn {
    tcp_conn_t *tcp_conn;
    ssl_layer_t *ssl_layer;
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
    double last_activity_time;
    int requests_sent_on_connection;
    bool closing;
    TAILQ_ENTRY(http_conn) entries;
} http_conn_t;

TAILQ_HEAD(http_conn_list_head, http_conn);
static struct http_conn_list_head g_http_conn_list;
static struct http_conn_list_head g_http_conn_pool;
static http_conn_t g_http_conn_pool_storage[MAX_CONN_SIZE];

static ev_timer g_client_stall_timer;
static void client_stall_check_cb(struct ev_loop *loop, ev_timer *w, int revents);

static void http_on_connect(struct tcp_conn *conn, int status);
static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len);
static void https_on_read(struct tcp_conn *conn, const char *data, ssize_t len);
static void http_on_write(struct tcp_conn *conn);
static void http_on_close(struct tcp_conn *conn);
static void return_http_conn_to_pool(http_conn_t *http_conn);

static tcp_callbacks_t http_callbacks = {
    .on_connect = http_on_connect,
    .on_read = http_on_read,
    .on_write = http_on_write,
    .on_close = http_on_close,
};

static void on_handshake_complete_cb_client(ssl_layer_t *layer) {
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, s_ex_data_idx);
    if (http_conn) {
        http_conn->last_activity_time = ev_now(g_main_loop);
        LOG_INFO("SSL handshake complete for client %p", http_conn);
        STATS_INC(connections_opened);
        STATS_INC(requests_sent);
        metrics_inc_success();
        metrics_update_cps(1); // Increment CPS for HTTPS
        http_conn->request_send_time = ev_now(g_main_loop);
        LOG_INFO("HTTP write data: %s.", http_conn->send_buffer);
        ssl_layer_write_app_data(http_conn->ssl_layer, http_conn->send_buffer, http_conn->send_buffer_size);
    } else {
        LOG_ERROR("No HTTP connection data associated with SSL layer during handshake complete");
    }
}

static void on_encrypted_data_cb_client(ssl_layer_t *layer, const void *data, int len) {
    LOG_DEBUG("HTTP on_encrypted_data_cb_client len:%d.", len);
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, s_ex_data_idx);
    if (http_conn) {
        http_conn->last_activity_time = ev_now(g_main_loop);
        tcp_layer_write(http_conn->tcp_conn, data, len);
    } else {
        LOG_ERROR("No HTTP connection data associated with SSL layer during encrypted data callback");
    }
}

static void on_decrypted_data_cb_client(ssl_layer_t *layer, const void *data, int len) {
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, s_ex_data_idx);
    if (http_conn) {
        http_conn->last_activity_time = ev_now(g_main_loop);
        http_on_read(http_conn->tcp_conn, data, len);
    } else {
        LOG_ERROR("No HTTP connection data associated with SSL layer during decrypted data callback");
    }
}

void http_client_init(perf_config_t *config) {
    TAILQ_INIT(&g_http_conn_list);
    TAILQ_INIT(&g_http_conn_pool);

    for (int i = 0; i < MAX_CONN_SIZE; i++) {
        TAILQ_INSERT_TAIL(&g_http_conn_pool, &g_http_conn_pool_storage[i], entries);
    }

    g_path_requests_count = config->http_config.paths_count;
    g_path_requests = (path_request_data_t*)malloc(g_path_requests_count * sizeof(path_request_data_t));

    for (int i = 0; i < g_path_requests_count; i++) {
        http_path_config_t *path_config = &config->http_config.paths[i];
        path_request_data_t *path_request = &g_path_requests[i];

        size_t headers_len = 0;
        for (int j = 0; j < path_config->request_headers_count; j++) {
            headers_len += strlen(path_config->request_headers[j]) + 2; // for \r\n
        }

        path_request->request_size = snprintf(NULL, 0, "GET %s HTTP/1.1\r\nHost: %s\r\n", path_config->path, config->l3.dst_ip_start) + headers_len + 2;
        path_request->request = (char*)malloc(path_request->request_size + 1);
        
        char *p = path_request->request;
        p += sprintf(p, "GET %s HTTP/1.1\r\nHost: %s\r\n", path_config->path, config->l3.dst_ip_start);
        for (int j = 0; j < path_config->request_headers_count; j++) {
            p += sprintf(p, "%s\r\n", path_config->request_headers[j]);
        }
        sprintf(p, "\r\n");
    }

    tcp_layer_init_local_port_pool(config);

    if (config->use_https) {
        if (ssl_layer_init_client() != 0) {
            LOG_ERROR("Failed to initialize client SSL layer");
            return;
        }
    }
    ev_timer_init(&g_client_stall_timer, client_stall_check_cb, 1., 1.);
    ev_timer_start(g_main_loop, &g_client_stall_timer);
}


static void client_stall_check_cb(struct ev_loop *loop, ev_timer *w, int revents) {
#if 0
    http_conn_t *http_conn;
    http_conn_t *stalled_connections_to_close[MAX_STALLED_TO_CLOSE_PER_TICK];
    int stalled_count = 0;
    double now = ev_now(loop);

    // First pass: identify stalled connections
    TAILQ_FOREACH(http_conn, &g_http_conn_list, entries) {
        if (now - http_conn->last_activity_time > 10.0) {
            LOG_WARN("Identified stalled client connection %p", http_conn);
            stalled_connections_to_close[stalled_count++] = http_conn;
            if (stalled_count >= MAX_STALLED_TO_CLOSE_PER_TICK) {
                break; // Stop collecting if array is full
            }
        }
    }

    // Second pass: close identified stalled connections
    for (int i = 0; i < stalled_count; i++) {
        http_conn = stalled_connections_to_close[i];
        LOG_WARN("Closing stalled client connection %p", http_conn);

        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        // We set on_close to NULL because we are managing the removal and
        // resource cleanup right here, and the normal on_close would
        // try to remove it from g_http_conn_list again.
        http_conn->tcp_conn->callbacks.on_close = NULL;
        tcp_layer_close(http_conn->tcp_conn);
        STATS_DEC(tcp_concurrent);
        STATS_INC(connections_closed);
        //return_http_conn_to_pool(http_conn);
    }
#endif
}

void create_http_connection(struct ev_loop *loop, perf_config_t *config) {
    //static int counter = 0;
    //if (counter ++ > 100000) return;

    http_conn_t *http_conn = TAILQ_FIRST(&g_http_conn_pool);
    if (!http_conn) {
        LOG_WARN("http_conn_pool is empty");
        return;
    }
    TAILQ_REMOVE(&g_http_conn_pool, http_conn, entries);

    memset(http_conn, 0, sizeof(http_conn_t));
    http_conn->closing = false;
    http_conn->last_activity_time = ev_now(g_main_loop);
    http_conn->config = config;
    http_conn->recv_buffer_size = MAX_RECV_SIZE;

    if (g_path_requests_count > 0) {
        int path_index = g_next_path_index;
        g_next_path_index = (g_next_path_index + 1) % g_path_requests_count;

        http_conn->send_buffer = g_path_requests[path_index].request;
        http_conn->send_buffer_size = g_path_requests[path_index].request_size;
    } else {
        http_conn->send_buffer = NULL;
        http_conn->send_buffer_size = 0;
    }
    LOG_DEBUG("Connecting to %s:%d", config->l3.dst_ip_start, config->l4.dst_port_start);
    tcp_callbacks_t http_cbs = http_callbacks;
    if (config->use_https) {
        http_cbs.on_read = https_on_read;
    }

    if (tcp_layer_connect(loop, config, 0, &http_cbs, http_conn, &http_conn->tcp_conn) != 0) {
        LOG_ERROR("Failed to create TCP connection.");
        if (http_conn->send_buffer) {
            http_conn->send_buffer = NULL;
        }
        TAILQ_INSERT_HEAD(&g_http_conn_pool, http_conn, entries);
        return;
    }

    if (config->use_https) {
        http_conn->ssl_layer = ssl_layer_create(0, on_handshake_complete_cb_client, on_encrypted_data_cb_client, on_decrypted_data_cb_client); // 0 for is_client
        if (!http_conn->ssl_layer) {
            LOG_ERROR("Failed to create client SSL layer");
            tcp_layer_close(http_conn->tcp_conn);
            return;
        }
        SSL_set_ex_data(http_conn->ssl_layer->ssl, s_ex_data_idx, http_conn); // Use index 0 for http_conn
    }
    
    TAILQ_INSERT_TAIL(&g_http_conn_list, http_conn, entries);
    STATS_INC(tcp_concurrent);
}

static void http_on_connect(struct tcp_conn *conn, int status) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    http_conn->last_activity_time = ev_now(g_main_loop);
    LOG_DEBUG("HTTP layer received connect callback from TCP layer. Status: %d", status);
    if (status == 0) {
        if (http_conn->config->use_https) {
            ssl_layer_handshake(http_conn->ssl_layer);
        } else {
            LOG_INFO("HTTP connection established.");
            STATS_INC(connections_opened);
            STATS_INC(requests_sent);
            metrics_inc_success();
            metrics_update_cps(1); // Increment CPS for HTTP
            http_conn->request_send_time = ev_now(g_main_loop);
            LOG_INFO("HTTP write data: %s.", http_conn->send_buffer);
            tcp_layer_write(conn, http_conn->send_buffer, http_conn->send_buffer_size);
            http_conn->data_received = 0;
            http_conn->header_length = 0;
            http_conn->content_length = 0;
            STATS_INC(http_req_sent);
        }
    } else {
        LOG_DEBUG("HTTP connection failed to connect.");
        STATS_INC(http_conn_fails);
        metrics_inc_failure();
        STATS_DEC(tcp_concurrent);
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        // No need to call tcp_layer_close as it's already being closed by TCP layer
        conn->upper_layer_data = NULL;
        return_http_conn_to_pool(http_conn);
    }
}

static void https_on_read(struct tcp_conn *conn, const char *data, ssize_t len) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    http_conn->last_activity_time = ev_now(g_main_loop);

    LOG_DEBUG("https_on_read, len: %zd", len);
    if (http_conn->config->use_https && len > 0) {
        ssl_layer_read_net_data(http_conn->ssl_layer, data, len);
        return;
    }
}
static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len) {
    LOG_DEBUG("http_on_read, len: %zd", len);
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    http_conn->last_activity_time = ev_now(g_main_loop);
    if (len <= 0) {
        return;
    }

    http_conn->total_received += len;
    LOG_DEBUG("HTTP read: %zd", len);

    // Buffer data only if we are still waiting for the full header.
    if (http_conn->header_length == 0) {
        if (http_conn->data_received + len > http_conn->recv_buffer_size) {
            LOG_ERROR("Buffer overflow while reading header, closing.");
            STATS_INC(http_rsp_hdr_overflow);
            tcp_layer_close(conn);
            return;
        }
        memcpy(http_conn->recv_buffer + http_conn->data_received, data, len);
        http_conn->data_received += len;
    }

    // Try to parse the header if we haven't already.
    if (http_conn->header_length == 0 && http_conn->data_received > 0) {
        if (strncmp(http_conn->recv_buffer, "HTTP", 4) != 0) {
            LOG_DEBUG("Malformed response does not start with HTTP, discarding. Data: %.*s", (int)http_conn->data_received, http_conn->recv_buffer);
            http_conn->data_received = 0; // Discard garbage
            STATS_INC(http_rsp_bad_hdrs);
            return;
        }

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
            STATS_INC(responses_received);

            http_conn->content_length = 0;
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
        } else if (pret == -1) {
            STATS_INC(http_rsp_hdr_parse_err);
            LOG_ERROR("HTTP response parse error, closing. Malformed data: %.*s", (int)http_conn->data_received, http_conn->recv_buffer);
            tcp_layer_close(conn);
            return;
        }
        // If pret == -2, header is incomplete. We will wait for more data.
    }

    // If header is parsed, check if we have received/drained the full body.
    if (http_conn->header_length > 0) {
        if (http_conn->total_received >= http_conn->header_length + http_conn->content_length) {
            
            // This is the non-keep-alive case.
            LOG_DEBUG("Full response received, closing connection.");
            STATS_INC(http_rsp_recv_full);
            tcp_layer_close(conn);
            // NOTE: Any data that arrived in the same buffer as the end of the body is discarded.
            // This is fine for non-keep-alive, but will break pipelining.
        }
    }
}

static void http_on_write(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    http_conn->last_activity_time = ev_now(g_main_loop);
    if (http_conn->config->use_https) {
        // Data has been written to the SSL_BIO, nothing to do here directly for HTTPS
        // The ssl_layer_write_app_data already sends encrypted data via on_encrypted_data_cb_client
    } else {
        http_conn->sent_size = http_conn->send_buffer_size;
        // Data has been written, we can send more if needed.
        // In this simple case, we send the whole request at once.
    }
}

static void return_http_conn_to_pool(http_conn_t *http_conn)
{
    if (http_conn->config->use_https && http_conn->ssl_layer) {
        ssl_layer_destroy(http_conn->ssl_layer);
        http_conn->ssl_layer = NULL;
    }
    if (http_conn->send_buffer) {
        http_conn->send_buffer = NULL;
    }
    TAILQ_INSERT_HEAD(&g_http_conn_pool, http_conn, entries);
}

static void http_on_close(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    LOG_DEBUG("http_on_close on client");
    if (http_conn && !http_conn->closing) {
        http_conn->closing = true;
        conn->upper_layer_data = NULL; // Prevent re-entry from other callbacks

        STATS_DEC(tcp_concurrent);
        STATS_INC(connections_closed);
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        return_http_conn_to_pool(http_conn);
    }
}

void http_client_cleanup(void) {
    if (g_path_requests) {
        for (int i = 0; i < g_path_requests_count; i++) {
            free(g_path_requests[i].request);
        }
        free(g_path_requests);
    }
}

void http_client_close_excess_connections(int excess) {
    http_conn_t *http_conn;
    int closed = 0;
    
    TAILQ_FOREACH(http_conn, &g_http_conn_list, entries) {
        if (closed >= excess) {
            break;
        }
        if (!http_conn->closing) {
            tcp_layer_close(http_conn->tcp_conn);
            closed++;
        }
    }
}
