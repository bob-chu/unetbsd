#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>

#include <signal.h>
#include <ev.h>
#include <init.h>

#include "config.h"
#include "dpdk_client.h" // Moved before gen_if.h
#include "gen_if.h"
#include "logger.h"
#include "server.h"
#include "client.h"
#include "metrics.h"
#include "scheduler.h"
#include "pipe_client.h"

struct ev_loop *g_main_loop;

static void sig_cb(EV_P_ ev_signal *w, int revents) {
    printf("Received signal %d, cleaning up and exiting.\n", w->signum);
    ev_break(loop, EVBREAK_ALL);
}

static void timer_10ms_cb(EV_P_ ev_timer *w, int revents)
{
    user_hardclock();
}

static void timer_1s_cb(EV_P_ ev_timer *w, int revents) {
    const char *mode = (const char *)w->data;
    scheduler_check_phase_transition(mode);
}

struct idle_watcher_data {
    dpdk_config_t *dpdk_config;
    const char *mode;
};

static void idle_cb(EV_P_ ev_idle *w, int revents) {
    struct idle_watcher_data *data = (struct idle_watcher_data *)w->data;
    dpdk_config_t *config = data->dpdk_config;
    const char *mode = data->mode;

    if (config->is_dpdk_client) {
        dpdk_client_read();
    } else {
        dpdk_read();
    }
    netbsd_loop();
}

int main(int argc, char *argv[]) {
    char *mode = NULL;
    char *config_path = NULL;
    char *socket_path = NULL;

    g_main_loop = ev_default_loop(0);

    ev_signal sigint_watcher;
    ev_signal_init(&sigint_watcher, sig_cb, SIGINT);
    ev_signal_start(g_main_loop, &sigint_watcher);

    ev_signal sigterm_watcher;
    ev_signal_init(&sigterm_watcher, sig_cb, SIGTERM);
    ev_signal_start(g_main_loop, &sigterm_watcher);

    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"socket-path", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    // Parse command-line arguments using getopt_long
    while ((opt = getopt_long(argc, argv, "s:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                socket_path = optarg;
                break;
            case '?':
                fprintf(stderr, "Usage: %s [options] <client|server|standalone> <config.json>\n", argv[0]);
                return 1;
        }
    }

    // After getopt_long, optind is the index of the first non-option argument
    // There should be two non-option arguments: mode and config_path
    if (argc - optind < 2) {
        fprintf(stderr, "Usage: %s [options] <client|server|standalone> <config.json>\n", argv[0]);
        return 1;
    }

    mode = argv[optind];
    config_path = argv[optind + 1];

    logger_init();
    logger_set_level(LOG_LEVEL_WARN);
    //logger_set_level(LOG_LEVEL_DEBUG);
    logger_enable_colors(1);

    printf("Starting in %s mode with config file: %s\n", mode, config_path);

    perf_config_t config;
    if (parse_config(config_path, &config) != 0) {
        fprintf(stderr, "Failed to parse config file.\n");
        return 1;
    }

    printf("Config parsed successfully.\n");

    metrics_init();

    netbsd_init();


    sysctl_tun("tcp_msl_loop", 1);      // 0.5 seconds (PR_SLOWHZ=2)
    sysctl_tun("tcp_msl_local", 1);     // 1 second
    sysctl_tun("tcp_msl_remote", 2);    // 2 seconds

    sysctl_tun("tcp_delack_ticks", 1);
    sysctl_tun("somaxconn", 262144);
    sysctl_tun("tcbhashsize", 8192*8);

    char *ip_addr_start;
    char *ip_addr_end;
    char *gateway_addr;
    dpdk_config_t *dpdk_config = NULL;

    if (strcmp(mode, "server") == 0) {
        dpdk_config = &config.dpdk_server;
        ip_addr_start = config.l3.dst_ip_start;
        ip_addr_end = config.l3.dst_ip_end;
        gateway_addr = config.l3.src_ip_start;
        prctl(PR_SET_NAME, "perf_server");
    } else if (strcmp(mode, "client") == 0) {
        dpdk_config = &config.dpdk_client;
        ip_addr_start = config.l3.src_ip_start;
        ip_addr_end = config.l3.src_ip_end;
        gateway_addr = config.l3.dst_ip_start;
        prctl(PR_SET_NAME, "perf_client");
    } else if (strcmp(mode, "standalone") == 0) {
        dpdk_config = &config.dpdk_client; // Assuming client for standalone
        ip_addr_start = config.l3.src_ip_start;
        ip_addr_end = config.l3.src_ip_end;
        gateway_addr = config.l3.dst_ip_start;
        prctl(PR_SET_NAME, "perf_standalone");
    } else {
        LOG_ERROR("Invalid mode: %s. Choose 'client' or 'server'.\n", mode);
        free_config(&config);
        return 1;
    }

    if (dpdk_config) {
        if (dpdk_config->is_dpdk_client) {
            if (dpdk_client_init(dpdk_config) != 0) {
                fprintf(stderr, "Failed to initialize DPDK client.\n");
                free_config(&config);
                return 1;
            }
            open_dpdk_client_interface(dpdk_config->iface);
        } else {
            char dpdk_args[512];
            snprintf(dpdk_args, sizeof(dpdk_args), "-l%d %s", dpdk_config->core_id, dpdk_config->args);
            char *dpdk_args_copy = strdup(dpdk_args);
            char *dpdk_argv[64];
            int dpdk_argc = 0;
            dpdk_argv[dpdk_argc++] = "tt"; // Dummy program name
            char *token = strtok(dpdk_args_copy, " ");
            while (token != NULL && dpdk_argc < 63) {
                dpdk_argv[dpdk_argc++] = token;
               	token = strtok(NULL, " ");
            }
            dpdk_argv[dpdk_argc] = NULL;

            dpdk_init(dpdk_argc, dpdk_argv);
            open_interface(dpdk_config->iface);
            free(dpdk_args_copy);
        }
    }

    struct in_addr start_ip, end_ip;

    LOG_DEBUG("ip_addr_start: %s, ip_addr_end: %s", ip_addr_start, ip_addr_end);
    if (inet_pton(AF_INET, ip_addr_start, &start_ip) == 1 &&
        inet_pton(AF_INET, ip_addr_end, &end_ip) == 1) {
        uint32_t start = ntohl(start_ip.s_addr);
        uint32_t end = ntohl(end_ip.s_addr);
        LOG_DEBUG("start: %lu, end: %lu", start, end);
        
        if (start <= end) {
            for (uint32_t i = 0; i <= (end - start); i++) {
                struct in_addr current_addr;
                current_addr.s_addr = htonl(start + i);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &current_addr, ip_str, INET_ADDRSTRLEN);
                LOG_DEBUG("current_addr.s_addr: %d, str: %s", current_addr.s_addr, ip_str);

                if (i == 0) {
                    LOG_DEBUG("ip_str: %s, gateway: %s.\n", ip_str, gateway_addr);
                    configure_interface(ip_str, gateway_addr);
                } else {
                    char ip[256];
                    snprintf(ip, sizeof(ip), "add ip: %s:%u inet %s netmask 255.255.255.0",
                             dpdk_config->iface, i - 1, ip_str);
                    LOG_DEBUG("IP: %s:ip_str: %s.\n", ip, ip_str);
                    add_interface_ip(ip_str);
                }
            }
        } else {
            configure_interface(ip_addr_start, gateway_addr);
        }
    } else {
        configure_interface(ip_addr_start, gateway_addr);
    }

    set_mtu(config.interface.mtu);

    if (socket_path) {
        printf("Using socket path: %s\n", socket_path);
        int is_client = (strcmp(mode, "client") == 0) ? 1 : 0;
        int offset_index = is_client ? config.dpdk_client.client_ring_idx : config.dpdk_server.client_ring_idx;
        pipe_client_init(g_main_loop, socket_path, is_client, offset_index);
        scheduler_set_paused(true); // Pause scheduler if pipe socket is enabled
    }

    //g_main_loop = EV_DEFAULT;
    ev_timer timer_10ms_watcher;
    ev_timer timer_1s_watcher;
    ev_idle idle_watcher;

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(g_main_loop, &timer_10ms_watcher);

    ev_timer_init(&timer_1s_watcher, timer_1s_cb, 1.0, 1.0);
    timer_1s_watcher.data = (void *)mode; // Pass mode to the watcher
    ev_timer_start(g_main_loop, &timer_1s_watcher);

    struct idle_watcher_data idle_data = {dpdk_config, (const char *)mode};
    ev_idle_init(&idle_watcher, idle_cb);
    idle_watcher.data = (void *)&idle_data; // Pass both config and mode
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
