#ifndef CLIENT_H
#define CLIENT_H

#include "config.h"
#include <ev.h>

void run_client(struct ev_loop *loop, perf_config_t *config);
void tcp_client_init(perf_config_t *config);
void udp_client_init(perf_config_t *config);

int client_get_current_target_connections(void);

#endif // CLIENT_H
