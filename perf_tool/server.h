#ifndef SERVER_H
#define SERVER_H

#include "config.h"
#include <ev.h>

void run_server(struct ev_loop *loop, perf_config_t *config);

#endif // SERVER_H
