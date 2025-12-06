#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <ev.h>
#include <u_socket.h>

#include "server.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"

void run_server(struct ev_loop *loop, perf_config_t *config) {
    scheduler_init(loop, config);

    if (strcmp(config->l4.protocol, "TCP") == 0) {
        http_server_init(config);
    } else if (strcmp(config->l4.protocol, "UDP") == 0) {
        udp_server_init(config);
    } else {
        LOG_ERROR("Unsupported protocol: %s", config->l4.protocol);
    }
}
