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
#include "ssl_layer.h"
#include "deps/picohttpparser/picohttpparser.h"

#define MAX_RECV_SIZE 1024*10
extern struct ev_loop *g_main_loop;


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
    int requests_sent_on_connection;
    TAILQ_ENTRY(http_conn) entries;
} http_conn_t;

TAILQ_HEAD(http_conn_list_head, http_conn);
static struct http_conn_list_head g_http_conn_list;

static void http_on_connect(struct tcp_conn *conn, int status);
static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len);
static void https_on_read(struct tcp_conn *conn, const char *data, ssize_t len);
static void http_on_write(struct tcp_conn *conn);
static void http_on_close(struct tcp_conn *conn);

static tcp_callbacks_t http_callbacks = {
    .on_connect = http_on_connect,
    .on_read = http_on_read,
    .on_write = http_on_write,
    .on_close = http_on_close,
};

static void on_handshake_complete_cb_client(ssl_layer_t *layer) {
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, 0);
    if (http_conn) {
        LOG_INFO("SSL handshake complete for client %p", http_conn);
        // Now that handshake is complete, send the first HTTP request
        scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
        scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
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
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, 0);
    if (http_conn) {
        scheduler_inc_stat(STAT_BYTES_SENT, len); // Track sent bytes for bandwidth
        tcp_layer_write(http_conn->tcp_conn, data, len);
    } else {
        LOG_ERROR("No HTTP connection data associated with SSL layer during encrypted data callback");
    }
}

static void on_decrypted_data_cb_client(ssl_layer_t *layer, const void *data, int len) {
    http_conn_t *http_conn = (http_conn_t*)SSL_get_ex_data(layer->ssl, 0);
    if (http_conn) {
        scheduler_inc_stat(STAT_BYTES_RECEIVED, len); // Track received bytes for bandwidth
        http_on_read(http_conn->tcp_conn, data, len);
    } else {
        LOG_ERROR("No HTTP connection data associated with SSL layer during decrypted data callback");
    }
}

void http_client_init(perf_config_t *config) {
    TAILQ_INIT(&g_http_conn_list);
    tcp_layer_init_local_port_pool(config);

    if (config->use_https) {
        if (ssl_layer_init_client() != 0) {
            LOG_ERROR("Failed to initialize client SSL layer");
            return;
        }
    }
}

void create_http_connection(struct ev_loop *loop, perf_config_t *config) {
    //static int counter = 0;
    //if (counter++ > 0) return;

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
    tcp_callbacks_t http_cbs = http_callbacks;
    if (config->use_https) {
        http_cbs.on_read = https_on_read;
    }

    if (tcp_layer_connect(loop, config, 0, &http_cbs, http_conn, &http_conn->tcp_conn) != 0) {
        LOG_ERROR("Failed to create TCP connection.");
        if (http_conn->send_buffer) {
            free(http_conn->send_buffer);
            http_conn->send_buffer = NULL;
        }
        if (http_conn) {
            free(http_conn);
            http_conn = NULL;
        }
        //tcp_layer_return_local_port(local_port);
        return;
    }

    if (config->use_https) {
        http_conn->ssl_layer = ssl_layer_create(0, on_handshake_complete_cb_client, on_encrypted_data_cb_client, on_decrypted_data_cb_client); // 0 for is_client
        if (!http_conn->ssl_layer) {
            LOG_ERROR("Failed to create client SSL layer");
            tcp_layer_close(http_conn->tcp_conn);
            return;
        }
        SSL_set_ex_data(http_conn->ssl_layer->ssl, 0, http_conn); // Use index 0 for http_conn
    }
    
    TAILQ_INSERT_TAIL(&g_http_conn_list, http_conn, entries);
    scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, 1);
}

static void http_on_connect(struct tcp_conn *conn, int status) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    LOG_DEBUG("HTTP layer received connect callback from TCP layer. Status: %d", status);
    if (status == 0) {
        if (http_conn->config->use_https) {
            ssl_layer_handshake(http_conn->ssl_layer);
        } else {
            LOG_INFO("HTTP connection established.");
            scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
            scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
            metrics_inc_success();
            metrics_update_cps(1); // Increment CPS for HTTP
            http_conn->request_send_time = ev_now(g_main_loop);
            LOG_INFO("HTTP write data: %s.", http_conn->send_buffer);
            tcp_layer_write(conn, http_conn->send_buffer, http_conn->send_buffer_size);
        }
    } else {
        LOG_DEBUG("HTTP connection failed to connect.");
        metrics_inc_failure();
        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);
        // No need to call tcp_layer_close as it's already being closed by TCP layer
        if (http_conn) {
            if (http_conn->send_buffer) {
                free(http_conn->send_buffer);
                http_conn->send_buffer = NULL;
            }
            free(http_conn);
            conn->upper_layer_data = NULL;
        }
    }
}

static void https_on_read(struct tcp_conn *conn, const char *data, ssize_t len) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;

    LOG_DEBUG("https_on_read", len);
    if (http_conn->config->use_https && len > 0) {
        ssl_layer_read_net_data(http_conn->ssl_layer, data, len);
        return;
    }
}
static void http_on_read(struct tcp_conn *conn, const char *data, ssize_t len) {
    LOG_DEBUG("http_on_read", len);
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    if (len <= 0) {
        return;
    }

    http_conn->total_received += len;
    LOG_DEBUG("HTTP read: %zd", len);

    // Buffer data only if we are still waiting for the full header.
    if (http_conn->header_length == 0) {
        if (http_conn->data_received + len > http_conn->recv_buffer_size) {
            LOG_ERROR("Buffer overflow while reading header, closing.");
            tcp_layer_close(conn);
            return;
        }
        memcpy(http_conn->recv_buffer + http_conn->data_received, data, len);
        http_conn->data_received += len;
    }

    // Try to parse the header if we haven't already.
    if (http_conn->header_length == 0 && http_conn->data_received > 0) {
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
            LOG_ERROR("HTTP response parse error, closing.");
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
            tcp_layer_close(conn);
            // NOTE: Any data that arrived in the same buffer as the end of the body is discarded.
            // This is fine for non-keep-alive, but will break pipelining.
        }
    }
}

static void http_on_write(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    if (http_conn->config->use_https) {
        // Data has been written to the SSL_BIO, nothing to do here directly for HTTPS
        // The ssl_layer_write_app_data already sends encrypted data via on_encrypted_data_cb_client
    } else {
        http_conn->sent_size = http_conn->send_buffer_size;
        // Data has been written, we can send more if needed.
        // In this simple case, we send the whole request at once.
    }
}

static void http_on_close(struct tcp_conn *conn) {
    http_conn_t *http_conn = (http_conn_t *)conn->upper_layer_data;
    LOG_DEBUG("http_on_close on client");
    if (http_conn) {
        conn->upper_layer_data = NULL; // Prevent re-entry from other callbacks

        scheduler_inc_stat(STAT_CONCURRENT_CONNECTIONS, -1);
        scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
        TAILQ_REMOVE(&g_http_conn_list, http_conn, entries);

        if (http_conn->config->use_https && http_conn->ssl_layer) {
            ssl_layer_destroy(http_conn->ssl_layer);
            http_conn->ssl_layer = NULL;
        }

        if (http_conn->send_buffer) {
            free(http_conn->send_buffer);
            http_conn->send_buffer = NULL;
        }
        free(http_conn);
    }
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
        // Free the resources here since on_close won't be called
        if (http_conn->config->use_https && http_conn->ssl_layer) {
            ssl_layer_destroy(http_conn->ssl_layer);
            http_conn->ssl_layer = NULL;
        }
        if (http_conn->send_buffer) {
            free(http_conn->send_buffer);
            http_conn->send_buffer = NULL;
        }
        if (http_conn) {
            free(http_conn);
            http_conn = NULL;
        }
        closed++;
    }
}
