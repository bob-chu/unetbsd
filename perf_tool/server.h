#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include <ev.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <u_socket.h>
#include <arpa/inet.h>

#include "picohttpparser.h"
#include "tcp_layer.h"
#include "ssl_layer.h"

#define BUFFER_SIZE 7000

typedef struct client_data {
    tcp_conn_t *tcp_conn;
    ssl_layer_t *ssl_layer;
    perf_config_t *config;
    char *recv_buffer;
    size_t recv_buffer_size;
    size_t recv_pos;
    int cleaning_up;
    const char *response_header;
    size_t header_size;
    int header_sent;
    int in_use;
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    struct phr_header req_headers[16];
    size_t num_headers;
    char *response_body;
    size_t response_body_size;
    size_t response_sent;
    size_t total_sent;
    double last_activity_time;
    TAILQ_ENTRY(client_data) free_list_entry;
} client_data_t;

extern struct ev_loop *g_main_loop;

void run_server(struct ev_loop *loop, perf_config_t *config);
void free_response_buffers(void);
void http_server_init(perf_config_t *config);
void udp_server_init(perf_config_t *config);
client_data_t *get_client_data_from_pool(void);
void return_client_data_to_pool(client_data_t *client_data);
void http_server_cleanup(perf_config_t *config);

#endif // SERVER_H
