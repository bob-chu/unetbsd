#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <stdlib.h>

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

    sysctl_tun("tcp_msl_loop", 1);      // 0.5 seconds (PR_SLOWHZ=2)
    sysctl_tun("tcp_msl_local", 1);     // 1 second
    sysctl_tun("tcp_msl_remote", 2);    // 2 seconds

    sysctl_tun("tcp_delack_ticks", 1);
    sysctl_tun("somaxconn", 262144);
    sysctl_tun("tcbhashsize", 8192);

    dpdk_init(dpdk_argc, dpdk_argv);
    open_interface(config.dpdk.iface);
    set_mtu(config.interface.mtu);

    free(dpdk_args_copy);

    char *ip_addr_start;
    char *ip_addr_end;
    char *gateway_addr;

    if (strcmp(mode, "server") == 0) {
        ip_addr_start = config.l3.dst_ip_start;
        ip_addr_end = config.l3.dst_ip_end;
        gateway_addr = config.l3.src_ip_start;
        prctl(PR_SET_NAME, "perf_server");
    } else if (strcmp(mode, "client") == 0) {
        ip_addr_start = config.l3.src_ip_start;
        ip_addr_end = config.l3.src_ip_end;
        gateway_addr = config.l3.dst_ip_start;
        prctl(PR_SET_NAME, "perf_client");
    } else if (strcmp(mode, "standalone") == 0) {
        ip_addr_start = config.l3.src_ip_start;
        ip_addr_end = config.l3.src_ip_end;
        gateway_addr = config.l3.dst_ip_start;
        prctl(PR_SET_NAME, "perf_standalone");
    } else {
        LOG_ERROR("Invalid mode: %s. Choose 'client' or 'server'.\n", mode);
        free_config(&config);
        return 1;
    }

    struct in_addr start_ip, end_ip;
    if (inet_pton(AF_INET, ip_addr_start, &start_ip) == 1 &&
        inet_pton(AF_INET, ip_addr_end, &end_ip) == 1) {
        uint32_t start = ntohl(start_ip.s_addr);
        uint32_t end = ntohl(end_ip.s_addr);

        if (start <= end) {
            for (uint32_t i = 0; i <= (end - start); i++) {
                struct in_addr current_addr;
                current_addr.s_addr = htonl(start + i);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &current_addr, ip_str, INET_ADDRSTRLEN);

                if (i == 0) {
                    configure_interface(ip_str, gateway_addr);
                } else {
                    char ip[256];
                    snprintf(ip, sizeof(ip), "add ip: %s:%u inet %s netmask 255.255.255.0",
                             config.dpdk.iface, i - 1, ip_str);
                    add_interface_ip(ip_str);
                }
            }
        } else {
            configure_interface(ip_addr_start, gateway_addr);
        }
    } else {
        configure_interface(ip_addr_start, gateway_addr);
    }


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

    if (strcmp(mode, "client") == 0) {
        http_client_cleanup();
    } else if (strcmp(mode, "server") == 0) {
        http_server_cleanup(&config);
    }

    free_config(&config);

    return 0;
}
