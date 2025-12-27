#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ev.h>
#include <u_socket.h>

#include "client.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"
#include "tcp_layer.h"

static struct ev_loop *g_main_loop;

int g_current_target_connections = 0;
int g_current_target_total_connections = 0;
double g_current_send_rate = 0.0;

static ev_timer client_scheduler_watcher;
static ev_timer client_idle_watcher;

static void client_scheduler_cb(EV_P_ ev_timer *w, int revents);
static void client_idle_cb(EV_P_ ev_timer *w, int revents);

void run_client(struct ev_loop *loop, perf_config_t *config) {
    LOG_INFO("Starting client setup...");
    g_main_loop = loop;

    tcp_layer_init_local_port_pool(config);

    scheduler_init(loop, config);

    ev_timer_init(&client_scheduler_watcher, client_scheduler_cb, 0., 0.05);
    client_scheduler_watcher.data = config;
    ev_timer_start(loop, &client_scheduler_watcher);

    ev_timer_init(&client_idle_watcher, client_idle_cb, 0.001, 0.001);
    client_idle_watcher.data = config;
    ev_timer_start(loop, &client_idle_watcher);

    if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
        http_client_init(config);
    } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
        udp_client_init(config);
    } else {
        LOG_ERROR("Unsupported objective type: %s", config->objective.type);
    }
}

static void client_scheduler_cb(EV_P_ ev_timer *w, int revents) {
    perf_config_t *config = (perf_config_t *)w->data;
    test_phase_t current_phase = scheduler_get_current_phase();

    switch (current_phase) {
        case PHASE_PREPARE:
            break;
        case PHASE_RAMP_UP: {
            double elapsed_in_phase = scheduler_get_current_time() - scheduler_get_current_phase_start_time();
            double progress = elapsed_in_phase / config->scheduler.ramp_up_duration_sec;
            if (progress > 1.0) progress = 1.0;

            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = (int)(config->objective.value * progress + 0.99);
                if (g_current_target_connections < 1 && config->objective.value > 0) {
                    g_current_target_connections = 1;
                }
            } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
                g_current_target_total_connections = (int)(config->objective.value * progress);
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value * progress;
                double interval = ev_timer_remaining(EV_A_ &client_scheduler_watcher);
                int packets_to_send = (int)(g_current_send_rate * interval);
                for (int i = 0; i < packets_to_send; ++i) {
                    send_udp_packet(EV_A_ config);
                }
            }
            break;
        }
        case PHASE_SUSTAIN: {
            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = config->objective.value;
            } else if (strcmp(config->objective.type, "TOTAL_CONNECTIONS") == 0) {
                g_current_target_total_connections = config->objective.value;
                if (scheduler_get_stats()->connections_opened >= g_current_target_total_connections) {
                    scheduler_set_current_phase(PHASE_CLOSE);
                }
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value;
                double interval = ev_timer_remaining(EV_A_ &client_scheduler_watcher);
                int packets_to_send = (int)(g_current_send_rate * interval);
                for (int i = 0; i < packets_to_send; ++i) {
                    send_udp_packet(EV_A_ config);
                }
            }
            break;
        }
        case PHASE_RAMP_DOWN: {
            double elapsed_in_phase = scheduler_get_current_time() - scheduler_get_current_phase_start_time();
            double progress = elapsed_in_phase / config->scheduler.ramp_down_duration_sec;
            if (progress > 1.0) progress = 1.0;

            if (strcmp(config->objective.type, "TCP_CONCURRENT") == 0 || strcmp(config->objective.type, "HTTP_REQUESTS") == 0) {
                g_current_target_connections = (int)(config->objective.value * (1.0 - progress));
            } else if (strcmp(config->objective.type, "UDP_STREAM") == 0) {
                g_current_send_rate = config->objective.value * (1.0 - progress);
            }
            break;
        }
        case PHASE_CLOSE:
            g_current_target_connections = 0;
            g_current_target_total_connections = 0;
            g_current_send_rate = 0.0;
            break;
        case PHASE_FINISHED:
            ev_timer_stop(EV_A_ w);
            ev_timer_stop(EV_A_ &client_idle_watcher);
            ev_break(EV_A_ EVBREAK_ALL);
            break;
    }
}

static void client_idle_cb(EV_P_ ev_timer *w, int revents) {
    perf_config_t *config = (perf_config_t *)w->data;
    double current_time = ev_now(EV_A);
    tcp_layer_update_port_stats_if_needed(current_time);
    test_phase_t phase = scheduler_get_current_phase();
    const char *type = config->objective.type;

    if (strcmp(type, "TCP_CONCURRENT") == 0 || strcmp(type, "HTTP_REQUESTS") == 0) {
#if 0
        int excess = (int)g_current_stats->tcp_concurrent - g_current_target_connections;
        if (excess > 0) {
            http_client_close_excess_connections(excess);
        }
#endif
        int connections_to_create = g_current_target_connections - (int)g_current_stats->tcp_concurrent;
        for (int i = 0; i < connections_to_create; i++) {
            if (g_current_stats->tcp_concurrent >= (uint64_t)g_current_target_connections) {
                break;
            }
            create_http_connection(EV_A_ config);
        }
    } else if (strcmp(type, "TOTAL_CONNECTIONS") == 0) {
        if (phase == PHASE_CLOSE) {
            ;//http_client_close_excess_connections((int)g_stats.tcp_concurrent);
        } else if (scheduler_get_stats()->connections_opened < (uint64_t)g_current_target_total_connections) {
            create_http_connection(EV_A_ config);
        }
    }
}

int client_get_current_target_connections(void) {
    return g_current_target_connections;
}
