#ifndef TCP_LAYER_H
#define TCP_LAYER_H

#include <ev.h>
#include <stdint.h>
#include "u_socket.h"
#include "config.h"

typedef struct tcp_conn tcp_conn_t;

typedef void (*tcp_on_connect_cb)(tcp_conn_t *conn, int error);
typedef void (*tcp_on_read_cb)(tcp_conn_t *conn, const char *data, ssize_t len);
typedef void (*tcp_on_write_cb)(tcp_conn_t *conn);
typedef void (*tcp_on_close_cb)(tcp_conn_t *conn);

typedef struct {
    tcp_on_connect_cb on_connect;
    tcp_on_read_cb on_read;
    tcp_on_write_cb on_write;
    tcp_on_close_cb on_close;
} tcp_callbacks_t;

typedef struct tcp_conn {
    struct ev_loop *loop;
    tcp_callbacks_t callbacks;
    void *upper_layer_data;
    struct netbsd_handle nh;
    int is_connected;
    ev_timer conn_timeout_timer;
    int local_port;
} tcp_conn_t;

typedef void (*tcp_on_accept_cb)(tcp_conn_t *conn);

typedef struct {
    tcp_on_accept_cb on_accept;
    tcp_callbacks_t conn_callbacks;
} tcp_server_callbacks_t;

int tcp_layer_connect(struct ev_loop *loop, perf_config_t *config, int server_port,
                      tcp_callbacks_t *callbacks, void *upper_layer_data, tcp_conn_t **conn_out);
ssize_t tcp_layer_write(tcp_conn_t *conn, const char *data, size_t len);
void tcp_layer_close(tcp_conn_t *conn);

int tcp_layer_server_init(perf_config_t *config, tcp_server_callbacks_t *callbacks);
void tcp_layer_server_cleanup(perf_config_t *config);

void tcp_layer_init_local_port_pool(perf_config_t *config);
int tcp_layer_get_local_port(void);
void tcp_layer_return_local_port(int port);
uint64_t tcp_layer_get_local_ports_used(void);
uint64_t tcp_layer_get_total_local_ports(void);
void tcp_layer_update_port_stats_if_needed(double current_time);

extern int g_current_server_port_index;
extern int g_server_port_count;
extern int *g_server_ports;

#endif // TCP_LAYER_H
