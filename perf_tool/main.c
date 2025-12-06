#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>
#include <init.h>

#include "config.h"
#include "gen_if.h"
#include "logger.h"
#include "server.h"
#include "client.h"
#include "metrics.h"
#include "scheduler.h"

struct ev_loop *g_main_loop;

static void timer_10ms_cb(EV_P_ ev_timer *w, int revents)
{
    user_hardclock();
}

static void timer_1s_cb(EV_P_ ev_timer *w, int revents) {
    const char *mode = (const char *)w->data;
    scheduler_check_phase_transition(mode);
}

static void idle_cb(EV_P_ ev_idle *w, int revents) {
    dpdk_read();
    netbsd_loop();
}

int main(int argc, char *argv[]) {
    const char *mode = argv[1];
    const char *config_path = argv[2];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <client|server|standalone> <config.json>\n", argv[0]);
        return 1;
    }

    printf("Starting in %s mode with config file: %s\n", mode, config_path);

    perf_config_t config;
    if (parse_config(config_path, &config) != 0) {
        fprintf(stderr, "Failed to parse config file.\n");
        return 1;
    }

    printf("Config parsed successfully.\n");

    logger_init();
    logger_set_level(LOG_LEVEL_WARN);
    //logger_set_level(LOG_LEVEL_DEBUG);
    logger_enable_colors(1);

    metrics_init();

    char *dpdk_args_copy = strdup(config.dpdk.args);
    char *dpdk_argv[64];
    int dpdk_argc = 0;
    dpdk_argv[dpdk_argc++] = "tt"; // Dummy program name
    char *token = strtok(dpdk_args_copy, " ");
    while (token != NULL && dpdk_argc < 63) {
        dpdk_argv[dpdk_argc++] = token;
        token = strtok(NULL, " ");
    }
    dpdk_argv[dpdk_argc] = NULL;

    netbsd_init();

    dpdk_init(dpdk_argc, dpdk_argv);
    open_interface(config.dpdk.iface);
    set_mtu(config.interface.mtu);

    free(dpdk_args_copy);

    char *ip_addr;
    char *gateway_addr;

    if (strcmp(mode, "server") == 0) {
        ip_addr = config.l3.dst_ip_start;
        gateway_addr = config.l3.src_ip_start;
    } else if (strcmp(mode, "client") == 0) {
        ip_addr = config.l3.src_ip_start;
        gateway_addr = config.l3.dst_ip_start;
    } else if (strcmp(mode, "standalone") == 0) {
        ip_addr = config.l3.src_ip_start;
        gateway_addr = config.l3.dst_ip_start;
    } else {
        LOG_ERROR("Invalid mode: %s. Choose 'client' or 'server'.\n", mode);
        free_config(&config);
        return 1;
    }
    configure_interface(ip_addr, gateway_addr);


    g_main_loop = EV_DEFAULT;
    ev_timer timer_10ms_watcher;
    ev_timer timer_1s_watcher;
    ev_idle idle_watcher;

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(g_main_loop, &timer_10ms_watcher);

    ev_timer_init(&timer_1s_watcher, timer_1s_cb, 1.0, 1.0);
    timer_1s_watcher.data = (void *)mode; // Pass mode to the watcher
    ev_timer_start(g_main_loop, &timer_1s_watcher);

    ev_idle_init(&idle_watcher, idle_cb);
    ev_idle_start(g_main_loop, &idle_watcher);

    if (strcmp(mode, "client") == 0) {
        run_client(g_main_loop, &config);
    } else if (strcmp(mode, "server") == 0) {
        run_server(g_main_loop, &config);
    } else if (strcmp(mode, "standalone") == 0) {
        printf("Running in standalone mode.\n");
    } else {
        fprintf(stderr, "Invalid mode: %s. Choose 'client' or 'server'.\n", mode);
        free_config(&config);
        return 1;
    }

    printf("Starting event loop.\n");
    ev_run(g_main_loop, 0);

    metrics_report();
    dpdk_cleanup();
    free_config(&config);
    free_response_buffers();

    return 0;
}
