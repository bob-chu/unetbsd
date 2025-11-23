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

#define MAX_RECV_SIZE 2048

typedef struct udp_conn_data {
    struct netbsd_handle nh;
    perf_config_t *config;
    char *send_buffer;
    size_t send_buffer_size;
    char recv_buffer[MAX_RECV_SIZE];
    size_t recv_buffer_size;
    double request_send_time;
    int local_port;
} udp_conn_data_t;

extern struct ev_loop *g_main_loop;

static void udp_client_conn_read_cb(void *handle, int events);

void udp_client_init(perf_config_t *config) {
    LOG_INFO("UDP Client initialized.");
}

void send_udp_packet(struct ev_loop *loop, perf_config_t *config) {
    udp_conn_data_t *conn_data = (udp_conn_data_t *)malloc(sizeof(udp_conn_data_t));
    if (!conn_data) {
        LOG_ERROR("Failed to allocate memory for UDP client data.");
        return;
    }
    memset(conn_data, 0, sizeof(udp_conn_data_t));
    conn_data->config = config;

    conn_data->nh.proto = PROTO_UDP;
    conn_data->nh.type = SOCK_DGRAM;
    conn_data->nh.is_ipv4 = 1;
    conn_data->nh.read_cb = NULL;
    conn_data->nh.write_cb = NULL;
    conn_data->nh.close_cb = NULL;
    conn_data->nh.data = NULL;
    conn_data->nh.active = 0;
    conn_data->nh.is_closing = 0;
    conn_data->nh.events = 0;
    conn_data->nh.on_event_queue = 0;

    if (netbsd_socket(&conn_data->nh) != 0) {
        LOG_ERROR("Failed to create UDP client socket: %s", strerror(errno));
        free(conn_data);
        return;
    }

    conn_data->local_port = tcp_layer_get_local_port();
    if (conn_data->local_port == -1) {
        LOG_ERROR("No available local ports for UDP packet.");
        netbsd_close(&conn_data->nh);
        free(conn_data);
        return;
    }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(conn_data->local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (netbsd_bind(&conn_data->nh, (struct sockaddr *)&local_addr) != 0) {
        LOG_ERROR("Failed to bind UDP socket to local port %d: %s", conn_data->local_port, strerror(errno));
        tcp_layer_return_local_port(conn_data->local_port);
        netbsd_close(&conn_data->nh);
        free(conn_data);
        return;
    }

    conn_data->send_buffer_size = config->client_payload.size;
    conn_data->send_buffer = (char *)malloc(conn_data->send_buffer_size);
    if (!conn_data->send_buffer) {
        LOG_ERROR("Failed to allocate memory for UDP send buffer.");
        tcp_layer_return_local_port(conn_data->local_port);
        netbsd_close(&conn_data->nh);
        free(conn_data);
        return;
    }
    memcpy(conn_data->send_buffer, config->client_payload.data, conn_data->send_buffer_size);

    conn_data->recv_buffer_size = sizeof(conn_data->recv_buffer);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    int server_port = g_server_ports[g_current_server_port_index];
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, config->network.dst_ip_start, &server_addr.sin_addr);

    g_current_server_port_index = (g_current_server_port_index + 1) % g_server_port_count;

    struct iovec iov;
    iov.iov_base = conn_data->send_buffer;
    iov.iov_len = conn_data->send_buffer_size;

    conn_data->request_send_time = ev_now(loop);
    ssize_t bytes_sent = netbsd_sendto(&conn_data->nh, &iov, 1, (struct sockaddr *)&server_addr);

    if (bytes_sent > 0) {
        scheduler_inc_stat(STAT_BYTES_SENT, bytes_sent);
        scheduler_inc_stat(STAT_REQUESTS_SENT, 1);
        metrics_inc_success();

        conn_data->nh.data = conn_data;
        conn_data->nh.read_cb = udp_client_conn_read_cb;
        conn_data->nh.write_cb = NULL;
        conn_data->nh.close_cb = NULL;
        conn_data->nh.active = 1;
        netbsd_io_start(&conn_data->nh);
    } else {
        LOG_ERROR("Failed to send UDP packet: %s", strerror(errno));
        metrics_inc_failure();
        tcp_layer_return_local_port(conn_data->local_port);
        netbsd_close(&conn_data->nh);
        free(conn_data->send_buffer);
        free(conn_data);
    }
}

static void udp_client_conn_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    udp_conn_data_t *conn_data = (udp_conn_data_t *)nh->data;

    struct iovec iov;
    iov.iov_base = conn_data->recv_buffer;
    iov.iov_len = conn_data->recv_buffer_size;
    struct sockaddr_in server_addr;
    ssize_t bytes_read = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&server_addr);

    if (bytes_read > 0) {
        scheduler_inc_stat(STAT_BYTES_RECEIVED, bytes_read);
        double response_recv_time = ev_now(g_main_loop);
        uint64_t latency_ms = (uint64_t)((response_recv_time - conn_data->request_send_time) * 1000);
        metrics_add_latency(latency_ms);
        metrics_inc_success();
        scheduler_inc_stat(STAT_RESPONSES_RECEIVED, 1);
    } else {
        metrics_inc_failure();
    }

    tcp_layer_return_local_port(conn_data->local_port);

    nh->read_cb = NULL;
    nh->write_cb = NULL;
    nh->close_cb = NULL;
    nh->data = NULL;
    nh->active = 0;
    nh->is_closing = 1;

    netbsd_close(&conn_data->nh);
    free(conn_data->send_buffer);
    free(conn_data);
}
