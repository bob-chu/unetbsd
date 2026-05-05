#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ev.h>
#include <getopt.h>
#include <sys/prctl.h>

#include "config.h"
#include "logger.h"
#include "dpdk_client.h"
#include "client.h"
#include "server.h"
#include "tcp_layer.h"
#include "scheduler.h"
#include "pipe_client.h"
#include "common.h" // Include common.h for lb_shared_info
#include <init.h>
#include <u_if.h>
#include <u_socket.h>
#include "gen_if.h"

struct ev_loop *g_main_loop;
char *g_mode = NULL;

// Global definition of idle_watcher_data
struct idle_watcher_data {
    dpdk_config_t *dpdk_config;
    const char *mode;
};

static void sig_cb(struct ev_loop *loop, ev_signal *w, int revents) {
    ev_break(loop, EVBREAK_ALL);
}

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents) {
    // Process DPDK read/write logic
    dpdk_read();
    
    // Periodically run NetBSD stack loop
    static double last_netbsd_loop = 0.0;
    double now = ev_now(loop);
    if (now - last_netbsd_loop > 0.001) { // 1ms
        netbsd_loop();
        last_netbsd_loop = now;
    }
}

extern int nb_procs;
extern int proc_id;

int main(int argc, char *argv[]) {
    logger_init();
    logger_set_level(LOG_LEVEL_INFO);

    char *mode = NULL;
    char *config_path = NULL;
    char *socket_path = NULL;

    g_main_loop = EV_DEFAULT;

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
        {"proc-id", required_argument, 0, 'p'},
        {"total-procs", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    // Parse command-line arguments using getopt_long
    while ((opt = getopt_long(argc, argv, "s:p:t:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 's':
                socket_path = optarg;
                break;
            case 'p':
                proc_id = atoi(optarg);
                break;
            case 't':
                nb_procs = atoi(optarg);
                break;
            case '?':
                fprintf(stderr, "Usage: %s [options] <client|server|standalone> <config.json>\n", argv[0]);
                return 1;
        }
    }

    // After getopt_long, optind is the index of the first non-option argument
    if (argc - optind < 2) {
        fprintf(stderr, "Usage: %s [options] <client|server|standalone> <config.json>\n", argv[0]);
        return 1;
    }

    mode = argv[optind];
    g_mode = mode;
    config_path = argv[optind + 1];

    LOG_INFO("Proc ID: %d, Total Procs: %d, Mode: %s", proc_id, nb_procs, mode);

    perf_config_t config;
    if (parse_config(config_path, &config) != 0) {
        LOG_ERROR("Failed to parse config file: %s\n", config_path);
        return 1;
    }
    LOG_INFO("Config parsed successfully.");

    metrics_init();

    char *ip_addr_start = NULL;
    char *ip_addr_end = NULL;
    char *gateway_addr = NULL;

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
    }

    dpdk_config_t *dpdk_config = NULL;
    if (strcmp(mode, "server") == 0) {
        dpdk_config = &config.dpdk_server;
    } else {
        dpdk_config = &config.dpdk_client;
    }

    if (dpdk_config) {
        char dpdk_args[512];
        snprintf(dpdk_args, sizeof(dpdk_args), "-l%d %s", dpdk_config->core_id, dpdk_config->args);
        char *dpdk_args_copy = strdup(dpdk_args);
        
        char *dpdk_argv[64];
        int dpdk_argc = 0;
        dpdk_argv[dpdk_argc++] = "tt"; // Dummy program name
        
        // Forced Isolated Primary Mode
        dpdk_argv[dpdk_argc++] = "--proc-type=primary";

        char *token = strtok(dpdk_args_copy, " ");
        while (token != NULL && dpdk_argc < 63) {
            if (strncmp(token, "--proc-type", 11) != 0) {
                if (strncmp(token, "--file-prefix=", 14) == 0) {
                    static char prefix_buf[128];
                    snprintf(prefix_buf, sizeof(prefix_buf), "%s_%d", token, proc_id);
                    dpdk_argv[dpdk_argc++] = prefix_buf;
                } else if (strncmp(token, "--vdev=", 7) == 0) {
                    static char vdev_buf[512];
                    strncpy(vdev_buf, token, sizeof(vdev_buf));
                    char *s = strstr(vdev_buf, "socket=");
                    if (s) {
                        char *comma = strchr(s, ',');
                        static char vdev_buf2[1024];
                        int base_len = s - vdev_buf + 7;
                        strncpy(vdev_buf2, vdev_buf, base_len);
                        char *p_start = s + 7;
                        char *p_end = comma ? comma : (vdev_buf + strlen(vdev_buf));
                        int p_len = p_end - p_start;
                        strncpy(vdev_buf2 + base_len, p_start, p_len);
                        snprintf(vdev_buf2 + base_len + p_len, sizeof(vdev_buf2) - (base_len + p_len), "_%d%s", proc_id, comma ? comma : "");
                        dpdk_argv[dpdk_argc++] = strdup(vdev_buf2);
                    } else {
                        dpdk_argv[dpdk_argc++] = strdup(vdev_buf);
                    }
                } else {
                    dpdk_argv[dpdk_argc++] = token;
                }
            }
            token = strtok(NULL, " ");
        }
        dpdk_argv[dpdk_argc] = NULL;

        LOG_INFO("Initializing DPDK with %d args:", dpdk_argc);
        for (int i = 0; i < dpdk_argc; i++) {
            LOG_INFO("  arg[%d]: %s", i, dpdk_argv[i]);
        }

        dpdk_init(dpdk_argc, dpdk_argv);
        open_interface(dpdk_config->iface);
        free(dpdk_args_copy);
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
                add_interface_ip(inet_ntoa(current_addr));
            }
        }
    }

    if (gateway_addr) {
        configure_interface(ip_addr_start, gateway_addr);
    }

    if (config.interface.mtu > 0) {
        set_mtu(config.interface.mtu);
    }

    if (strcmp(mode, "server") == 0) {
        run_server(g_main_loop, &config);
    } else if (strcmp(mode, "client") == 0) {
        run_client(g_main_loop, &config);
    }

    ev_idle idle_watcher;
    ev_idle_init(&idle_watcher, idle_cb);
    ev_idle_start(g_main_loop, &idle_watcher);

    LOG_INFO("Starting event loop.");
    printf("[PID: %d] Starting event loop...\n", getpid());
    fflush(stdout);
    ev_run(g_main_loop, 0);

    free_config(&config);
    return 0;
}
