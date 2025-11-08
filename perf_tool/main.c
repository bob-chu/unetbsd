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

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents) {
    dpdk_read();
    netbsd_process_event();
}

int main(int argc, char *argv[]) {
    const char *mode = argv[1];
    const char *config_path = argv[2];
    const char *if_name = argv[3];
    const char *file_prefix = argv[4];
    const char *coremask = argv[5];

    if (argc != 6) {
        fprintf(stderr, "Usage: %s <client|server> <config.json> <interface_name> <file_prefix> <coremask>\n", argv[0]);
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
    logger_enable_colors(1);

    metrics_init();

    char vdev_str[128];
    snprintf(vdev_str, sizeof(vdev_str), "eth_af_packet0,iface=%s,blocksz=4096,framesz=2048,framecnt=512,qpairs=1", if_name);
    //snprintf(vdev_str, sizeof(vdev_str), "eth_af_packet0,iface=%s,blocksz=4194304,framesz=8192,framecnt=512,qpairs=1", if_name);

    char file_prefix_str[128];
    snprintf(file_prefix_str, sizeof(file_prefix_str), "--file-prefix=%s", file_prefix);

    char lcores_str[128];
    snprintf(lcores_str, sizeof(lcores_str), "-l%s", coremask);

    char *dpdk_str[] = {
        "tt",
        lcores_str,
        "--vdev", vdev_str,
        "--proc-type=primary",
        file_prefix_str,
        "--no-huge"
    };
    int dpdk_argc = sizeof(dpdk_str) / sizeof(dpdk_str[0]);

    netbsd_init();

    dpdk_init(dpdk_argc, dpdk_str);
    open_interface(if_name);

    char *ip_addr;
    char *gateway_addr;

    if (strcmp(mode, "server") == 0) {
        ip_addr = config.network.dst_ip_start;
        gateway_addr = config.network.src_ip_start;
    } else if (strcmp(mode, "client") == 0) {
        ip_addr = config.network.src_ip_start;
        gateway_addr = config.network.dst_ip_start;
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
