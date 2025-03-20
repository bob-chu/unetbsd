#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h> /* htons */
#include <ev.h>
#include <init.h>
#include <netinet/in.h> /* IPPROTO_UDP, struct sockaddr_in, INADDR_ANY */
#include <openssl/md5.h>
#include <sys/socket.h>
#include <u_if.h>
#include <u_socket.h>

#include "tun.h"

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) ); \
})
#endif

#define BUF_SIZE 9000
#define PORT 12345
#define MAX_CLIENTS 4096
#define CURRENT_CLIENTS 8000

struct tcp_client {
    int read_flag;
    struct netbsd_handle handle;

};
static struct netbsd_handle udp_server;
static struct netbsd_handle tcp_server;
static struct tcp_client s_tcp_client[MAX_CLIENTS];
static struct tcp_client tcp_curr_client[CURRENT_CLIENTS];


static int cli_idx = 0;
static int cc_cli_count = 1000000000;
static int read_flag = 0;

static void tcp_read_cb(void *handle, int events);
static void tcp_write_cb(void *handle, int events);
static void tcp_close_cb(void *handle);
static void tcp_client_read_cb(void *handle, int events);
static void tcp_connect_cb(void *handle, int events);

static struct netbsd_handle *get_client() {
    if (cli_idx >= MAX_CLIENTS - 6)
        cli_idx = 0;
    return &s_tcp_client[cli_idx++].handle;
}

void tun_read_cb(EV_P_ ev_io *w, int revents) {
    int tun_fd = w->fd;
    unsigned char buffer[BUF_SIZE];
    int packet_len;

    packet_len = read(tun_fd, buffer, BUF_SIZE);
    if (packet_len < 0) {
        perror("read TUN device data failed");
        ev_break(EV_A_ EVBREAK_ALL);
        return;
    }

    af_packet_input(buffer, packet_len, NULL);
}

static void timer_10ms_cb(EV_P_ ev_timer *w, int revents)
{
    user_hardclock();
}

void cc_client_connect() {
    static int cur_cc_idx = 0;
    static int local_port = 2000;

    struct tcp_client *cli = &tcp_curr_client[cur_cc_idx];

    struct netbsd_handle *nh = &cli->handle;

    memset(nh, 0, sizeof(*nh));
    nh->read_cb = tcp_connect_cb;
    nh->write_cb = tcp_write_cb;
    nh->close_cb = tcp_close_cb;
    nh->is_ipv4 = 1;
    nh->type = SOCK_STREAM;
    nh->proto = IPPROTO_TCP;
    cli->read_flag = 0;

    if (netbsd_socket(nh) < 0) {
        printf("Can not open socket.\n");
        return;
    }
    int optval = 1;
    if (netbsd_reuseaddr(nh, &optval, sizeof(optval))) {
        printf("Set reuseaddr option failed.\n");
        netbsd_close(nh);
        return;
    }

    char *ip_str = "192.168.1.2";
    char *server_str = "192.168.1.1";
    struct sockaddr_in cli_addr, svr_addr;

    inet_pton(AF_INET, ip_str, &cli_addr);
    inet_pton(AF_INET, server_str, &svr_addr);

    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &cli_addr.sin_addr);
    cli_addr.sin_port = htons(local_port++);

    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    inet_pton(AF_INET, server_str, &svr_addr.sin_addr);
    svr_addr.sin_port = htons(12345);
    if (local_port > 65000) {
        local_port = 2000;
    }

    if (netbsd_bind(nh, (struct sockaddr *)&cli_addr)) {
        printf("Can not bind addr\n");
        netbsd_close(nh);
        return;
    }

    if (netbsd_connect(nh, (struct sockaddr *)&svr_addr)) {
        printf("Can not connect to server\n");
        netbsd_close(nh);
        return;
    }
    netbsd_io_start(nh);

    cur_cc_idx++;
    cur_cc_idx %= CURRENT_CLIENTS;
}

static void timer_1s_cb(EV_P_ ev_timer *w, int revents) {
    static int cc_count = 0;
    if (cc_count < cc_cli_count) {
        int i = 0;
        while (i < 10) {
            cc_client_connect();
            i++;
            cc_count++;
        }
    }
}

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents) {
    netbsd_process_event();
}

static void udp_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    char buffer[2048];
    struct iovec iov = {.iov_base = buffer, .iov_len = 2048};
    size_t bytes;
    struct sockaddr_storage from;

    bytes = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&from);
    if (bytes > 0) {

        iov.iov_len = bytes;
        ssize_t sent = netbsd_sendto(nh, &iov, 1, (struct sockaddr *)&from);
        if (sent < 0) {
            printf("Failed to send: %d\n", (int)sent);
        } else {
            printf("Sent %zd bytes back\n", sent);
        }
    } else if (bytes == 0) {
        printf("No data received\n");
    } else {
        printf("Read error: %zu\n", bytes);
        netbsd_close(nh);
    }
}

static void tcp_accept(void *handle, int events) {
    struct netbsd_handle *tcp_client = get_client();
    if (tcp_client == NULL) {
        return;
    }

    tcp_client->read_cb = tcp_read_cb;
    tcp_client->write_cb = tcp_write_cb;
    tcp_client->close_cb = tcp_close_cb;
    tcp_client->is_ipv4 = 1;

    if (netbsd_accept(&tcp_server, tcp_client)) {
        printf("Accept tcp client error\n");
        return;
    }

    netbsd_io_start(tcp_client);
}

static void tcp_connect_cb(void *handle, int events) {
    struct netbsd_handle *tcp_client = (struct netbsd_handle *)handle;
    struct tcp_client *cli = container_of(handle, struct tcp_client, handle);

    tcp_client->read_cb = tcp_client_read_cb;

    char *buffer = "1234";
    struct iovec iov = {.iov_base = buffer, .iov_len = strlen(buffer)};
    netbsd_write(tcp_client, &iov, 1);
    cli->read_flag = 1;
}

static void tcp_client_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;

    struct tcp_client *cli = container_of(handle, struct tcp_client, handle);

    char buffer[2048];
    struct iovec iov = {.iov_base = buffer, .iov_len = 2048};
    int bytes;
    struct sockaddr_storage from;

    bytes = netbsd_read(nh, &iov, 1);
    if (bytes > 0) {
        if (cli->read_flag) {
            netbsd_close(nh);
            return;
        }
        iov.iov_len = bytes;
        ssize_t sent = netbsd_write(nh, &iov, 1);
        if (sent < 0) {
            printf("Failed to send: %d\n", (int)sent);
        }
    } else {
        netbsd_close(nh);
        return;
    }
}
static void tcp_read_cb(void *handle, int events) {
    struct netbsd_handle *h = (struct netbsd_handle *)handle;
    if (h == &tcp_server) {
        return tcp_accept(h, events);
    } else {
        return tcp_client_read_cb(h, events);
    }
}
static void tcp_write_cb(void *handle, int events) {
    // printf("tcp write_cb.\n");
}
static void tcp_close_cb(void *handle) {
    netbsd_close(handle);
    // printf("tcp close_cb.\n");
}

static void udp_server_init() {
    udp_server.is_ipv4 = 1;
    udp_server.type = SOCK_DGRAM;
    udp_server.proto = IPPROTO_UDP;
    udp_server.read_cb = udp_read_cb;
    udp_server.active = 0;
    int ret = netbsd_socket(&udp_server);
    if (ret) {
        printf("netbsd create socket error: %d\n", ret);
    }
    udp_server.active = 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);

    ret = netbsd_bind(&udp_server, (struct sockaddr *)&addr);
    if (ret) {
        printf("bind error: %d\n", ret);
        netbsd_close(&udp_server);
    }

    netbsd_io_start(&udp_server);
    printf("udp udp_server listening on port 12345\n");
}

static void tcp_server_init() {
    struct sockaddr_in addr;

    tcp_server.is_ipv4 = 1;
    tcp_server.type = SOCK_STREAM;
    tcp_server.proto = IPPROTO_TCP;
    tcp_server.read_cb = tcp_read_cb;
    tcp_server.write_cb = tcp_write_cb;
    tcp_server.close_cb = tcp_close_cb;

    if (netbsd_socket(&tcp_server)) {
        printf("Failed to crete tcp server socket.\n");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);

    if (netbsd_bind(&tcp_server, (struct sockaddr *)&addr)) {
        printf("TCP server bind addr failed\n");
        netbsd_close(&tcp_server);
        return;
    }

    if (netbsd_listen(&tcp_server, 5)) {
        printf("TCP server listen  failed\n");
        netbsd_close(&tcp_server);
    }

    netbsd_io_start(&tcp_server);

    printf("TCP echo server listening on port 12345\n");
}

int main() {
    int tun_fd = -1;

    netbsd_init();
    tun_fd = open_af_packet();
    if (tun_fd < 0) {
        printf("Can not open tun device\n");
        return -1;
    }

    // 3. 初始化 libev 事件循环
    struct ev_loop *loop = EV_DEFAULT;
    ev_io tun_read_watcher;
    ev_idle idle_watcher;
    ev_timer timer_10ms_watcher;
    ev_timer timer_1s_watcher;

    // 4. 初始化并配置读事件 watcher
    ev_io_init(&tun_read_watcher, tun_read_cb, tun_fd, EV_READ);
    ev_io_start(loop, &tun_read_watcher);

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(loop, &timer_10ms_watcher);

    ev_timer_init(&timer_1s_watcher, timer_1s_cb, 1.0, 1.0);
    ev_timer_start(loop, &timer_1s_watcher);

    ev_idle_init(&idle_watcher, idle_cb);
    ev_idle_start(loop, &idle_watcher);

    printf("hello world\n");
    // 5. 运行 libev 事件循环
    udp_server_init();
    tcp_server_init();
    ev_run(loop, 0);

    close_af_packet();
    return 0;
}
