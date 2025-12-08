#ifndef CLIENT_H
#define CLIENT_H

#include "config.h"
#include <ev.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <u_socket.h>
#include <arpa/inet.h>

void run_client(struct ev_loop *loop, perf_config_t *config);
void http_client_init(perf_config_t *config);
void udp_client_init(perf_config_t *config);
void create_http_connection(struct ev_loop *loop, perf_config_t *config);
void send_udp_packet(struct ev_loop *loop, perf_config_t *config);

int client_get_current_target_connections(void);

void http_client_close_excess_connections(int excess);

#endif // CLIENT_H
