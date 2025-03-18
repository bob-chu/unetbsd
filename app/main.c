#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <string.h>
#include <sys/socket.h>
#include <init.h>
#include <u_if.h>
#include <u_socket.h>
#include <netinet/in.h>  /* IPPROTO_UDP, struct sockaddr_in, INADDR_ANY */
#include <arpa/inet.h>   /* htons */
#include <ev.h>
#include "tun.h"

#define BUF_SIZE 9000
#define PORT 12345
static struct netbsd_handle udp_server;
static struct netbsd_handle tcp_server;
static struct netbsd_handle tcp_client;

static void tcp_read_cb(void *handle, int events);
static void tcp_write_cb(void *handle, int events);
static void tcp_close_cb(void *handle);


// libev 读事件回调函数
void tun_read_cb(EV_P_ ev_io *w, int revents) {
    int tun_fd = w->fd;
    unsigned char buffer[BUF_SIZE];
    int packet_len;

    packet_len = read(tun_fd, buffer, BUF_SIZE);
    if (packet_len < 0) {
        perror("从 TUN 设备读取数据失败");
        ev_break(EV_A_ EVBREAK_ALL); // 发生错误，退出 libev 事件循环
        return;
    }

    af_packet_input(buffer, packet_len, NULL);
}

static void timer_10ms_cb(EV_P_ ev_timer *w, int revents)
{
    user_hardclock();
}

static void
idle_cb(struct ev_loop *loop, ev_idle *w, int revents)
{
    netbsd_process_event();
}

/* 读取回调：处理接收到的 UDP 数据并回显 */
static void
udp_read_cb(void *handle, int events)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    char buffer[2048];
    struct iovec iov = { .iov_base = buffer, .iov_len = 2048};
    size_t bytes;
    struct sockaddr_storage from;


    /* 读取数据 */
    bytes = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&from);
    if (bytes > 0) {
        printf("Received %zu bytes: %.*s\n", bytes, (int)bytes, buffer);

        /* 原样回显数据 */
        iov.iov_len = bytes; /* 只回显实际接收的字节数 */
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

static void tcp_accept(void *handle, int events)
{
    printf("tcp_accept: handle: %p\n", handle);
    static struct netbsd_handle *only_one = NULL;
    if (only_one != NULL) {
        printf("Client is already running, do not accept this new one\n");
        return;
    }
    if (netbsd_accept(&tcp_server, &tcp_client)) {
        printf("Accept tcp client error\n");
        return;
    }

    tcp_client.read_cb = tcp_read_cb;
    tcp_client.write_cb = tcp_write_cb;
    tcp_client.close_cb = tcp_close_cb;
    netbsd_io_start(&tcp_client);
}

static void tcp_client_read_cb(void *handle, int events)
{
    printf("tcp_client_read_cb: handle: %p\n", handle);
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    char buffer[2048];
    struct iovec iov = { .iov_base = buffer, .iov_len = 2048};
    int bytes;
    struct sockaddr_storage from;

    /* 读取数据 */
    bytes = netbsd_read(nh, &iov, 1);
    if (bytes > 0) {
        printf("Received %zu bytes: %.*s\n", bytes, (int)bytes, buffer);

        /* 原样回显数据 */
        iov.iov_len = bytes; /* 只回显实际接收的字节数 */
        ssize_t sent = netbsd_write(nh, &iov, 1);
        if (sent < 0) {
            printf("Failed to send: %d\n", (int)sent);
        } else {
            printf("Sent %zd bytes back\n", sent);
        }
    } else if (bytes <= 0) {
        printf("No data received, socket closed\n");
        netbsd_close(nh);
    }
}
static void
tcp_read_cb(void *handle, int events)
{
    struct netbsd_handle *h = (struct netbsd_handle *)handle;
    if (h == &tcp_server) {
        return tcp_accept(handle, events);
    } else {
        return tcp_client_read_cb(&tcp_client, events);
   }
}
static void
tcp_write_cb(void *handle, int events)
{
    printf("tcp write_cb.\n");
}
static void
tcp_close_cb(void *handle)
{
    netbsd_close(handle);
    printf("tcp close_cb.\n");
}

static void udp_server_init()
{
    udp_server.is_ipv4 = 1;
    udp_server.type = SOCK_DGRAM;
    udp_server.proto = IPPROTO_UDP;
    udp_server.read_cb = udp_read_cb;
    udp_server.active = 0;
    int ret  = netbsd_socket(&udp_server);
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

static void
tcp_server_init()
{
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

int main()
{
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

    // 4. 初始化并配置读事件 watcher
    ev_io_init(&tun_read_watcher, tun_read_cb, tun_fd, EV_READ);
    ev_io_start(loop, &tun_read_watcher);

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(loop, &timer_10ms_watcher);

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
