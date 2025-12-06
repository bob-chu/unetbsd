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
#define MAX_SEND_BUFFER_SIZE 1024*5

char *response_buffer_hello = NULL;
char *response_buffer_another = NULL;
char *response_buffer_default = NULL;
size_t response_size_hello = 0;
size_t response_size_another = 0;
size_t response_size_default = 0;

static client_data_t client_data_pool[CLIENT_DATA_POOL_SIZE];
TAILQ_HEAD(client_data_free_list, client_data);
static struct client_data_free_list free_client_data_list = TAILQ_HEAD_INITIALIZER(free_client_data_list);

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

    response_size_hello = config->http_config.response_size_hello;
    if (response_size_hello > 0) {
        response_buffer_hello = malloc(response_size_hello);
        int pos = 0;
        while (pos < (int)response_size_hello) {
            const char *word = words[rand() % word_count];
            int len = strlen(word);
            if (pos + len > (int)response_size_hello) len = response_size_hello - pos;
            memcpy(response_buffer_hello + pos, word, len);
            pos += len;
            if (pos < (int)response_size_hello) {
                response_buffer_hello[pos++] = ' ';
            }
        }
    }
    
    response_size_another = config->http_config.response_size_another;
    if (response_size_another > 0) {
        response_buffer_another = malloc(response_size_another);
        int pos = 0;
        while (pos < (int)response_size_another) {
            const char *word = words[rand() % word_count];
            int len = strlen(word);
            if (pos + len > (int)response_size_another) len = response_size_another - pos;
            memcpy(response_buffer_another + pos, word, len);
            pos += len;
            if (pos < (int)response_size_another) {
                response_buffer_another[pos++] = ' ';
            }
        }
    }
    
    response_size_default = config->http_config.response_size_default;
    if (response_size_default > 0) {
        response_buffer_default = malloc(response_size_default);
        int pos = 0;
        while (pos < (int)response_size_default) {
            const char *word = words[rand() % word_count];
            int len = strlen(word);
            if (pos + len > (int)response_size_default) len = response_size_default - pos;
            memcpy(response_buffer_default + pos, word, len);
            pos += len;
            if (pos < (int)response_size_default) {
                response_buffer_default[pos++] = ' ';
            }
        }
    }
}

void free_response_buffers(void) {
    free(response_buffer_hello);
    free(response_buffer_another);
    free(response_buffer_default);
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
    data->header_sent = 0;
    data->response_sent = 0;

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

    scheduler_inc_stat(STAT_CONNECTIONS_OPENED, 1);
    metrics_update_cps(1); // Increment CPS for HTTP or HTTPS connection
}

static void on_handshake_complete_cb(ssl_layer_t *layer) {
    LOG_INFO("SSL handshake complete");
    client_data_t *client_data = (client_data_t*)SSL_get_ex_data(layer->ssl, 0);
    if (client_data) {
        metrics_update_cps(1); // Increment CPS for HTTPS specifically on handshake completion
    }
}

static void on_encrypted_data_cb(ssl_layer_t *layer, const void *data, int len) {
    client_data_t *client_data = (client_data_t*)SSL_get_ex_data(layer->ssl, 0);
    if (client_data) {
        scheduler_inc_stat(STAT_BYTES_SENT, len); // Track sent bytes for bandwidth
        tcp_layer_write(client_data->tcp_conn, data, len);
    } else {
        LOG_ERROR("No client data associated with SSL layer");
    }
}

static void process_http_request(client_data_t *data, const char *buf, int nbytes) {
    tcp_conn_t *conn = data->tcp_conn;
    LOG_DEBUG("Enter process_http_request, nbytes: %d", nbytes);
    if (nbytes > 0) {
        size_t space = data->recv_buffer_size - data->recv_pos;
        size_t copy_len = ((size_t)nbytes < space) ? (size_t)nbytes : space;
        if (copy_len > 0) {
            memcpy(data->recv_buffer + data->recv_pos, buf, copy_len);
            data->recv_pos += copy_len;
        }
        scheduler_inc_stat(STAT_BYTES_RECEIVED, (int)copy_len);

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
            goto close_conn;
        }
        if (ret > 0) {
            LOG_INFO("Request parsed: %.*s %.*s HTTP/1.%d", (int)method_len, method, (int)path_len, path, minor_version);
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
        scheduler_inc_stat(STAT_BYTES_RECEIVED, nbytes); // Track received bytes for bandwidth
        process_http_request(data, buf, nbytes);
    } else {
        LOG_ERROR("No client data associated with SSL layer during decrypted data callback");
    }
}


static void http_request_read_cb(tcp_conn_t *conn, const char *buf, ssize_t nbytes) {
    client_data_t *data = (client_data_t *)conn->upper_layer_data;

    if (data->config->use_https) {
        ssl_layer_read_net_data(data->ssl_layer, buf, nbytes);
    } else {
        process_http_request(data, buf, nbytes);
    }
}


static void prepare_http_response(client_data_t *data) {
    char *body = NULL;
    size_t body_size = 0;
    if (data->path_len == 6 && strncmp(data->path, "/hello", 6) == 0) {
        body = response_buffer_hello;
        body_size = response_size_hello;
    } else if (data->path_len == 8 && strncmp(data->path, "/another", 8) == 0) {
        body = response_buffer_another;
        body_size = response_size_another;
    } else {
        body = response_buffer_default;
        body_size = response_size_default;
    }
    data->response_body = body;
    data->response_body_size = body_size;
    data->header_size = snprintf(data->response_header, sizeof(data->response_header),
                                 "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                                 body_size);
}

static ssize_t send_http_response(client_data_t *data, tcp_conn_t *conn) {
    ssize_t sent;
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
                scheduler_inc_stat(STAT_BYTES_SENT, sent);
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
                scheduler_inc_stat(STAT_BYTES_SENT, sent);
                data->response_sent += sent;
                body_remaining -= sent;
                data->total_sent += sent;
                LOG_DEBUG("Total sent: %zu, Body remain: %zu bytes", data->total_sent, body_remaining);
            } else {
                LOG_DEBUG("Partial HTTPS body send (%zd), waiting for next write event", data->total_sent);
                return data->total_sent;
            }
        }

    } else {
        // Send header
        size_t header_remaining = data->header_size - data->header_sent;
        while (header_remaining > 0) {
            sent = tcp_layer_write(conn, data->response_header + data->header_sent, header_remaining);
            if (sent > 0) {
                scheduler_inc_stat(STAT_BYTES_SENT, sent);
                data->header_sent += sent;
                header_remaining -= sent;
                data->total_sent += sent;
                LOG_DEBUG("Header sent: %zu bytes", sent);
            } else if (sent == 0 || (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                LOG_ERROR("Failed to send header: %zd (%s)", sent, strerror(errno));
                http_on_close(conn);
                tcp_layer_close(conn);
                return data->total_sent;
            } else {
                // EAGAIN or EWOULDBLOCK, wait for next write event
                LOG_DEBUG("Partial header send (%zd), waiting for next write event", data->total_sent);
                return data->total_sent;
            }
        }

        // Send body
        size_t body_remaining = data->response_body_size - data->response_sent;
        if (body_remaining > 0) {
            size_t chunk_size = (body_remaining > MAX_SEND_BUFFER_SIZE) ? MAX_SEND_BUFFER_SIZE : body_remaining;  // Send in chunks if large
            sent = tcp_layer_write(conn, data->response_body + data->response_sent, chunk_size);
            if (sent > 0) {
                scheduler_inc_stat(STAT_BYTES_SENT, sent);
                data->response_sent += sent;
                body_remaining -= sent;
                data->total_sent += sent;
                LOG_DEBUG("Total sent: %zu, Body remain: %zu bytes", data->total_sent, body_remaining);
            } else if (sent == 0 || (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                //LOG_ERROR("Failed to send body chunk: %zd (%s)", sent, strerror(errno));
                //http_on_close(conn);
                //tcp_layer_close(conn);
                return data->total_sent;
            } else {
                // EAGAIN or EWOULDBLOCK, wait for next write event
                LOG_DEBUG("Partial body send (%zd), waiting for next write event", data->total_sent);
                return data->total_sent;
            }
        }
    }


    // If everything is sent, log but do not close the connection, let the client handle closure
    if (data->response_body_size - data->response_sent == 0 && data->header_size - data->header_sent == 0) {
        LOG_DEBUG("Response fully sent (%zd bytes), waiting for client to close connection", data->total_sent);
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
    scheduler_inc_stat(STAT_CONNECTIONS_CLOSED, 1);
    return_client_data_to_pool(data);
}
