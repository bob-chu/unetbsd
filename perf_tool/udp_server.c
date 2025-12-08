#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <ev.h>
#include <u_socket.h>

#include "server.h"
#include "config.h"
#include "logger.h"
#include "metrics.h"
#include "scheduler.h"

#define MAX_RECV_SIZE 2048

typedef struct udp_listen_data {
    struct netbsd_handle nh;
    perf_config_t *config;
    int port;
} udp_listen_data_t;

static void udp_server_read_cb(void *handle, int events);

void udp_server_init(perf_config_t *config) {
    LOG_INFO("UDP Server initialized.");
    int start_port = config->l4.dst_port_start;
    int end_port = config->l4.dst_port_end;
    int num_ports = end_port - start_port + 1;
    for (int i = 0; i < num_ports; ++i) {
        int port = start_port + i;
        udp_listen_data_t *listen_data = (udp_listen_data_t *)malloc(sizeof(udp_listen_data_t));
        if (!listen_data) continue;
        memset(listen_data, 0, sizeof(udp_listen_data_t));
        listen_data->config = config;
        listen_data->port = port;

        listen_data->nh.proto = PROTO_UDP;
        listen_data->nh.type = SOCK_DGRAM;
        listen_data->nh.is_ipv4 = 1;
        listen_data->nh.read_cb = udp_server_read_cb;
        listen_data->nh.data = listen_data;

        if (netbsd_socket(&listen_data->nh) != 0) {
            LOG_ERROR("Failed to create UDP listen socket for port %d", port);
            free(listen_data);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (netbsd_bind(&listen_data->nh, (struct sockaddr *)&addr) != 0) {
            LOG_ERROR("Failed to bind UDP socket to port %d: %s", port, strerror(errno));
            netbsd_close(&listen_data->nh);
            free(listen_data);
            continue;
        }

        netbsd_io_start(&listen_data->nh);
        LOG_INFO("UDP Server listening on port %d", port);
    }
}

static void udp_server_read_cb(void *handle, int events) {
    if (!(events & EV_READ)) return;

    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    udp_listen_data_t *data = (udp_listen_data_t *)nh->data;

    char recv_buf[MAX_RECV_SIZE];
    struct sockaddr_in client_addr;
    struct iovec iov;
    iov.iov_base = recv_buf;
    iov.iov_len = MAX_RECV_SIZE;

    ssize_t bytes_read = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&client_addr);
    if (bytes_read > 0) {
        STATS_ADD(bytes_received, bytes_read);
        STATS_INC(requests_sent);  // Reuse for received

        if (data->config->server_response.size > 0) {
            struct iovec resp_iov;
            resp_iov.iov_base = data->config->server_response.data;
            resp_iov.iov_len = data->config->server_response.size;
            ssize_t bytes_sent = netbsd_sendto(nh, &resp_iov, 1, (struct sockaddr *)&client_addr);
            if (bytes_sent > 0) {
                            STATS_ADD(bytes_sent, bytes_sent);
                            STATS_INC(responses_received);
                            metrics_inc_success();            } else {
                metrics_inc_failure();
            }
        } else {
            metrics_inc_success();
        }
    } else {
        metrics_inc_failure();
    }
}
