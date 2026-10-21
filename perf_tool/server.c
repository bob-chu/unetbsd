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

static ev_timer server_stats_watcher;

static void server_stats_cb(EV_P_ ev_timer *w, int revents) {
    scheduler_report_connections("server");
}

void run_server(struct ev_loop *loop, perf_config_t *config) {
    scheduler_init(loop, config);

    if (strcmp(config->l4.protocol, "TCP") == 0) {
        http_server_init(config);
    } else if (strcmp(config->l4.protocol, "UDP") == 0) {
        udp_server_init(config);
    } else {
        LOG_ERROR("Unsupported protocol: %s", config->l4.protocol);
    }
    ev_timer_init(&server_stats_watcher, server_stats_cb, 0., 1.0);
    ev_timer_start(loop, &server_stats_watcher);
}
