#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>

#include <ev.h>
#include <u_socket.h>

#include "picohttpparser.h"

#include "server.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"
#include "tcp_layer.h"
#include "ssl_layer.h"

#define BUFFER_SIZE 7000
#define CLIENT_DATA_POOL_SIZE 16384
#define MAX_SEND_BUFFER_SIZE 1024*4

typedef struct {
    const char *path;
    char *response_body;
    size_t response_body_size;
    char *response_header;
    size_t response_header_size;
} path_response_data_t;

static path_response_data_t *g_path_responses = NULL;
static int g_path_responses_count = 0;

static client_data_t client_data_pool[CLIENT_DATA_POOL_SIZE];
TAILQ_HEAD(client_data_free_list, client_data);
static struct client_data_free_list free_client_data_list = TAILQ_HEAD_INITIALIZER(free_client_data_list);

static ev_timer g_server_stall_timer;
static void server_stall_check_cb(struct ev_loop *loop, ev_timer *w, int revents);

static void http_on_accept(tcp_conn_t *conn);
static void http_request_read_cb(tcp_conn_t *conn, const char *data, ssize_t len);
static void http_request_write_cb(tcp_conn_t *conn);
static void http_on_close(tcp_conn_t *conn);
static void prepare_http_response(client_data_t *data);
static ssize_t send_http_response(client_data_t *data, tcp_conn_t *conn);

static void on_handshake_complete_cb(ssl_layer_t *layer);
static void on_encrypted_data_cb(ssl_layer_t *layer, const void *data, int len);
static void on_decrypted_data_cb(ssl_layer_t *layer, const void *data, int len);


static tcp_server_callbacks_t server_callbacks;

void init_response_buffers(perf_config_t *config) {
    srand(time(NULL));
    const char *words[] = { "hello", "world", "random", "text", "human", "readable", "response", "server", "data", "content" };
    const int word_count = sizeof(words) / sizeof(words[0]);

    g_path_responses_count = config->http_config.paths_count;
    g_path_responses = (path_response_data_t*)malloc(g_path_responses_count * sizeof(path_response_data_t));

    for (int i = 0; i < g_path_responses_count; i++) {
        http_path_config_t *path_config = &config->http_config.paths[i];
        path_response_data_t *path_response = &g_path_responses[i];

        path_response->path = path_config->path;
        path_response->response_body_size = path_config->response_body_size;
        path_response->response_body = (char*)malloc(path_response->response_body_size);

        if (path_response->response_body_size > 0) {
            int pos = 0;
            while (pos < (int)path_response->response_body_size) {
                const char *word = words[rand() % word_count];
                int len = strlen(word);
                if (pos + len > (int)path_response->response_body_size) len = path_response->response_body_size - pos;
                memcpy(path_response->response_body + pos, word, len);
                pos += len;
                if (pos < (int)path_response->response_body_size) {
                    path_response->response_body[pos++] = ' ';
                }
            }
        }

        char temp_header[4096];
        char *p = temp_header;

        p += snprintf(p, sizeof(temp_header), "HTTP/1.1 200 OK\r\n");
        for (int j = 0; j < path_config->response_headers_count; j++) {
            p += snprintf(p, sizeof(temp_header) - (p - temp_header), "%s\r\n", path_config->response_headers[j]);
        }
        p += snprintf(p, sizeof(temp_header) - (p - temp_header), "Content-Length: %zu\r\n", path_response->response_body_size);
        p += snprintf(p, sizeof(temp_header) - (p - temp_header), "Connection: close\r\n\r\n");
        
        path_response->response_header_size = p - temp_header;
        path_response->response_header = (char*)malloc(path_response->response_header_size);
        memcpy(path_response->response_header, temp_header, path_response->response_header_size);
    }
}

void free_response_buffers(void) {
    if (g_path_responses) {
        for (int i = 0; i < g_path_responses_count; i++) {
            free(g_path_responses[i].response_body);
            free(g_path_responses[i].response_header);
        }
        free(g_path_responses);
    }
    for (int i = 0; i < CLIENT_DATA_POOL_SIZE; i++) {
        free(client_data_pool[i].recv_buffer);
        client_data_pool[i].recv_buffer = NULL;
    }
}

static void init_client_data_pool(perf_config_t *config) {
    TAILQ_INIT(&free_client_data_list);
    for (int i = 0; i < CLIENT_DATA_POOL_SIZE; i++) {
        client_data_t *client_data = &client_data_pool[i];
        memset(client_data, 0, sizeof(client_data_t));
        client_data->recv_buffer_size = BUFFER_SIZE;
        client_data->recv_buffer = (char *)malloc(client_data->recv_buffer_size);
        client_data->config = config;
        TAILQ_INSERT_TAIL(&free_client_data_list, client_data, free_list_entry);
    }
}

client_data_t *get_client_data_from_pool() {
    if (TAILQ_EMPTY(&free_client_data_list)) {
        return NULL;
    }
    client_data_t *client_data = TAILQ_FIRST(&free_client_data_list);
    TAILQ_REMOVE(&free_client_data_list, client_data, free_list_entry);
    client_data->in_use = 1;
    client_data->recv_pos = 0;
    client_data->header_sent = 0;
    client_data->response_sent = 0;
    return client_data;
}

void return_client_data_to_pool(client_data_t *client_data) {
    if (client_data->in_use) {
        if (client_data->ssl_layer) {
            ssl_layer_destroy(client_data->ssl_layer);
            client_data->ssl_layer = NULL;
        }
        client_data->recv_pos = 0;
        client_data->header_sent = 0;
        client_data->response_sent = 0;
        client_data->total_sent = 0;
        client_data->tcp_conn = NULL;
        client_data->in_use = 0;
        TAILQ_INSERT_TAIL(&free_client_data_list, client_data, free_list_entry);
    }
}

void http_server_init(perf_config_t *config) {
    init_response_buffers(config);
    init_client_data_pool(config);

    if (config->use_https) {
        if (ssl_layer_init_server(config->http_config.cert_path, config->http_config.key_path) != 0) {
            LOG_ERROR("Failed to initialize SSL layer");
            return;
        }
    }

    server_callbacks.on_accept = http_on_accept;

    if (tcp_layer_server_init(config, &server_callbacks) != 0) {
        LOG_ERROR("Failed to initialize TCP server layer");
        return;
    }

    ev_timer_init(&g_server_stall_timer, server_stall_check_cb, 1., 1.);
    ev_timer_start(g_main_loop, &g_server_stall_timer);
}

void server_stall_check_cb(struct ev_loop *loop, ev_timer *w, int revents) {
#if 0
    double now = ev_now(loop);
    for (int i = 0; i < CLIENT_DATA_POOL_SIZE; i++) {
        client_data_t *data = &client_data_pool[i];
        if (data->in_use) {
            if (now - data->last_activity_time > 5.0) {
                LOG_WARN("Server closing stalled connection %p", data->tcp_conn);
                //tcp_layer_close(data->tcp_conn);
                // try to re-send data
                http_request_write_cb(data->tcp_conn);
            }
        }
    }
#endif
}

void http_server_cleanup(perf_config_t *config) {
    tcp_layer_server_cleanup(config);
    free_response_buffers();
}

static void http_on_accept(tcp_conn_t *conn) {
    LOG_DEBUG("http_on_accept conn: %p", conn);
    client_data_t *data = get_client_data_from_pool();
    if (!data) {
        tcp_layer_close(conn);
        return;
    }

    data->tcp_conn = conn;
    conn->upper_layer_data = data;
    data->recv_pos = 0;
    data->header_size = 0;
    data->header_sent = 0;
    data->response_body_size = 0;
    data->response_sent = 0;
    data->last_activity_time = ev_now(g_main_loop);

    conn->callbacks.on_read = http_request_read_cb;
    conn->callbacks.on_write = http_request_write_cb;
    conn->callbacks.on_close = http_on_close;
    conn->callbacks.on_connect = NULL;

    if (data->config->use_https) {
        data->ssl_layer = ssl_layer_create(1, on_handshake_complete_cb, on_encrypted_data_cb, on_decrypted_data_cb); // 1 for is_server
        if (!data->ssl_layer) {
            LOG_ERROR("Failed to create SSL layer");
            http_on_close(conn);
            tcp_layer_close(conn);
            return;
        }
        // Associate the ssl_layer with the client_data for callbacks
        SSL_set_ex_data(data->ssl_layer->ssl, 0, data); // Use index 0 for client_data
    }

    STATS_INC(tcp_concurrent);
    STATS_INC(connections_opened);
    metrics_update_cps(1); // Increment CPS for HTTP or HTTPS connection
}

static void on_handshake_complete_cb(ssl_layer_t *layer) {
    LOG_INFO("SSL handshake complete");
    client_data_t *client_data = (client_data_t*)SSL_get_ex_data(layer->ssl, 0);
    if (client_data) {
        client_data->last_activity_time = ev_now(g_main_loop);
        metrics_update_cps(1); // Increment CPS for HTTPS specifically on handshake completion
    }
}

static void on_encrypted_data_cb(ssl_layer_t *layer, const void *data, int len) {
    client_data_t *client_data = (client_data_t*)SSL_get_ex_data(layer->ssl, 0);
    if (client_data) {
        client_data->last_activity_time = ev_now(g_main_loop);
        tcp_layer_write(client_data->tcp_conn, data, len);
    } else {
        LOG_ERROR("No client data associated with SSL layer");
    }
}

static void process_http_request(client_data_t *data, const char *buf, int nbytes) {
    tcp_conn_t *conn = data->tcp_conn;
    data->last_activity_time = ev_now(g_main_loop);
    LOG_DEBUG("Enter process_http_request, nbytes: %d", nbytes);
    if (nbytes > 0) {
        size_t space = data->recv_buffer_size - data->recv_pos;
        size_t copy_len = ((size_t)nbytes < space) ? (size_t)nbytes : space;
        if (copy_len > 0) {
            memcpy(data->recv_buffer + data->recv_pos, buf, copy_len);
            data->recv_pos += copy_len;
        }

        const char *method = NULL;
        size_t method_len = 0;
        const char *path = NULL;
        size_t path_len = 0;
        int minor_version = 0;
        size_t num_headers_local = 16;
        int ret = phr_parse_request(data->recv_buffer, data->recv_pos,
                                    &method, &method_len, &path, &path_len,
                                    &minor_version, data->req_headers, &num_headers_local, 0);
        LOG_DEBUG("phr_parse_request, ret: %d", ret);
        if (ret == -1) {
            LOG_ERROR("Parse error on request, closing connection");
            STATS_INC(http_rep_hdr_parse_err);
            goto close_conn;
        }
        if (ret > 0) {
            LOG_INFO("Request parsed: %.*s %.*s HTTP/1.%d", (int)method_len, method, (int)path_len, path, minor_version);
            STATS_INC(http_req_rcvd);
            data->method = method;
            data->method_len = method_len;
            data->path = path;
            data->path_len = path_len;
            data->num_headers = num_headers_local;
            prepare_http_response(data);
            data->header_sent = 0;
            data->response_sent = 0;
            send_http_response(data, conn);
            LOG_DEBUG("Total response bytes sent: %zd", data->total_sent);
            size_t remaining = data->recv_pos - ret;
            if (remaining > 0) {
                memmove(data->recv_buffer, data->recv_buffer + ret, remaining);
            }
            data->recv_pos = remaining;
            return;
        } else if (data->recv_pos == data->recv_buffer_size) {
            goto close_conn;
        }
        return;
    } else {
        goto close_conn;
    }

close_conn:
    http_on_close(conn);
    tcp_layer_close(conn);
}

static void on_decrypted_data_cb(ssl_layer_t *layer, const void *buf, int nbytes) {
    client_data_t *data = (client_data_t*)SSL_get_ex_data(layer->ssl, 0);
    if (data) {
        data->last_activity_time = ev_now(g_main_loop);
        process_http_request(data, buf, nbytes);
    } else {
        LOG_ERROR("No client data associated with SSL layer during decrypted data callback");
    }
}


static void http_request_read_cb(tcp_conn_t *conn, const char *buf, ssize_t nbytes) {
    client_data_t *data = (client_data_t *)conn->upper_layer_data;
    data->last_activity_time = ev_now(g_main_loop);

    if (data->config->use_https) {
        ssl_layer_read_net_data(data->ssl_layer, buf, nbytes);
    } else {
        process_http_request(data, buf, nbytes);
    }
}


static void prepare_http_response(client_data_t *data) {
    for (int i = 0; i < g_path_responses_count; i++) {
        if (data->path_len == strlen(g_path_responses[i].path) && 
            strncmp(data->path, g_path_responses[i].path, data->path_len) == 0) {
            data->response_body = g_path_responses[i].response_body;
            data->response_body_size = g_path_responses[i].response_body_size;
            data->response_header = g_path_responses[i].response_header;
            data->header_size = g_path_responses[i].response_header_size;
            return;
        }
    }

    // Default case if no path matches
    // You may want to handle this differently, e.g., send a 404 response.
    // For now, we'll send an empty response, and the connection will be closed.
    data->response_body = NULL;
    data->response_body_size = 0;
    data->response_header = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
    data->header_size = strlen(data->response_header);
}

static ssize_t send_http_response(client_data_t *data, tcp_conn_t *conn) {
    ssize_t sent;
    data->last_activity_time = ev_now(g_main_loop);
    LOG_DEBUG("send_http_response, conn:%p", conn);

    if (data->config->use_https) {
        client_data_t *check_data = SSL_get_ex_data(data->ssl_layer->ssl, 0);
        if (check_data != data) {
            LOG_ERROR("FATAL: SSL context corruption on conn=%p! expected_ctx=%p, actual_ctx=%p",
                      conn, data, check_data);
            abort();
        }

        // Send header
        size_t header_remaining = data->header_size - data->header_sent;
        while (header_remaining > 0) {
            sent = ssl_layer_write_app_data(data->ssl_layer, data->response_header + data->header_sent, header_remaining);
            if (sent > 0) {
                data->header_sent += sent;
                header_remaining -= sent;
                data->total_sent += sent;
                LOG_DEBUG("HTTPS Header sent: %zu bytes", sent);
            } else {
                LOG_DEBUG("Partial HTTPS header send (%zd), waiting for next write event", data->total_sent);
                return data->total_sent;
            }
        }

        // Send body
        size_t body_remaining = data->response_body_size - data->response_sent;
        if (body_remaining > 0) {
            size_t chunk_size = (body_remaining > MAX_SEND_BUFFER_SIZE) ? MAX_SEND_BUFFER_SIZE : body_remaining;  // Send in chunks if large
            sent = ssl_layer_write_app_data(data->ssl_layer, data->response_body + data->response_sent, chunk_size);
            if (sent > 0) {
                data->response_sent += sent;
                body_remaining -= sent;
                data->total_sent += sent;
                LOG_DEBUG("Total sent: %zu, Body remain: %zu bytes", data->total_sent, body_remaining);
            } else if (sent < 0) {
                LOG_ERROR("Failed to send body chunk via SSL, closing connection.");
                tcp_layer_close(conn);
                return data->total_sent;
            } else { // sent == 0
                LOG_DEBUG("Partial HTTPS body send (%zd), waiting for next write event", data->total_sent);
                return data->total_sent;
            }
        }

    } else {
        // Send header
        if (data->header_sent < data->header_size) {
            sent = tcp_layer_write(conn, data->response_header + data->header_sent, data->header_size - data->header_sent);
            if (sent > 0) {
                if (data->header_sent == 0) {
                    STATS_INC(http_rsp_hdr_send);
                }
                data->header_sent += sent;
                data->total_sent += sent;
                LOG_DEBUG("Header sent: %zu bytes", sent);
            } else if (sent < 0/* && errno != EAGAIN && errno != EWOULDBLOCK*/) {
                LOG_ERROR("Failed to send header: %zd (%s)", sent, strerror(errno));
                STATS_INC(http_rsp_hdr_send_err);
                http_on_close(conn);
                tcp_layer_close(conn);
                goto out;
                //return data->total_sent;
            } else {
                // EAGAIN or EWOULDBLOCK (sent == 0 or sent < 0), wait for next write event
                LOG_DEBUG("Partial header send (%zd), waiting for next write event", data->total_sent);
                goto out;
                //return data->total_sent;
            }
        }

        // Send body
        if (data->response_sent < data->response_body_size) {
            size_t body_remaining = data->response_body_size - data->response_sent;
            size_t chunk_size = (body_remaining > MAX_SEND_BUFFER_SIZE) ? MAX_SEND_BUFFER_SIZE : body_remaining;  // Send in chunks if large
            sent = tcp_layer_write(conn, data->response_body + data->response_sent, chunk_size);
            if (sent > 0) {
                if (data->response_sent == 0) {
                    STATS_INC(http_rsp_body_send);
                }
                data->response_sent += sent;
                data->total_sent += sent;
                LOG_DEBUG("Total sent: %zu, Body remain: %zu bytes", data->total_sent, data->response_body_size - data->response_sent);
            } else if (sent < 0/* && errno != EAGAIN && errno != EWOULDBLOCK*/) {
                LOG_ERROR("Failed to send body chunk: %zd (%s)", sent, strerror(errno));
                STATS_INC(http_rsp_body_send_err);
                //http_on_close(conn);
                //tcp_layer_close(conn);
                goto out;
                //return data->total_sent;
            } else {
                // EAGAIN or EWOULDBLOCK (sent == 0 or sent < 0), wait for next write event
                LOG_DEBUG("Partial body send (%zd), waiting for next write event", data->total_sent);
                goto out;
                //return data->total_sent;
            }
        }
    }

out:
    // If everything is sent, log but do not close the connection, let the client handle closure
    if (data->response_body_size > 0 && data->response_body_size == data->response_sent && data->header_size == data->header_sent) {
        LOG_DEBUG("Response fully sent (%zd bytes), waiting for client to close connection", data->total_sent);
        STATS_INC(http_rsp_body_send_done);
    }

    return data->total_sent;
}

static void http_request_write_cb(tcp_conn_t *conn) {
    client_data_t *data = (client_data_t *)conn->upper_layer_data;
    if (data->response_sent < data->response_body_size || data->header_sent < data->header_size) {
        ssize_t sent = send_http_response(data, conn);
        LOG_DEBUG("Write callback processed, total sent: %zd bytes", sent);
    } else {
        LOG_DEBUG("Response already fully sent, ignoring write callback");
    }
}

static void http_on_close(tcp_conn_t *conn) {
    client_data_t *data = (client_data_t *)conn->upper_layer_data;
    STATS_DEC(tcp_concurrent);
    STATS_INC(connections_closed);
    return_client_data_to_pool(data);
}
