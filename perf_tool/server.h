#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include <ev.h>

void run_server(struct ev_loop *loop, perf_config_t *config);
void init_response_buffers(perf_config_t *config);
void free_response_buffers(void);

#endif // SERVER_H
