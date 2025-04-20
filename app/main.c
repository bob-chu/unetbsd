#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>

#include <arpa/inet.h> /* htons */
#include <ev.h>
#include <init.h>
#include <netinet/in.h> /* IPPROTO_UDP, struct sockaddr_in, INADDR_ANY */
//#include <openssl/md5.h>
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
    int connect_flag;
    struct netbsd_handle handle;
    char *write_ptr;
    int write_sz;
};
static struct netbsd_handle udp_server;
static struct netbsd_handle tcp_server;
static struct tcp_client s_tcp_client[MAX_CLIENTS];
static struct tcp_client tcp_curr_client[CURRENT_CLIENTS];


static int cli_idx = 0;
static int cc_cli_count = 10;
static int read_flag = 0;
static int total_accept_cls = 0;

static void tcp_read_cb(void *handle, int events);
static void tcp_write_cb(void *handle, int events);
static void tcp_close_cb(void *handle, int events);
static void tcp_client_read_cb(void *handle, int events);
static void tcp_connect_cb(void *handle, int events);

#define TARGET_CONTENT_LENGTH 2000000

static char *html;
static int html_len;

static void generate_html()
{
    time_t now = time(NULL);
    struct tm tm = *gmtime(&now);
    char date_str[128];
    strftime(date_str, sizeof(date_str), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    html = malloc(TARGET_CONTENT_LENGTH + 1024);

    char body[] = "<!DOCTYPE html>\r\n"
                  "<html lang=\"en\">\r\n"
                  "<head>\r\n"
                  "<meta charset=\"UTF-8\">\r\n"
                  "<title>Welcome to UnetStack!</title>\r\n"
                  "<style>\r\n"
                  "    body {\r\n"
                  "        width: 35em;\r\n"
                  "        margin: 0 auto;\r\n"
                  "        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
                  "    }\r\n"
                  "</style>\r\n"
                  "</head>\r\n"
                  "<body>\r\n"
                  "<h1>Welcome to UnetStack!</h1>\r\n"
                  "<p>For online documentation and support please refer to\r\n"
                  "<a href=\"http://unetstack.org/\">unetstack.org</a>.</p>\r\n"
                  "<p><em>Thank you for using UnetStack.</em></p>\r\n"
                  "</body>\r\n"
                  "</html>\r\n";

    char ending_string[] = "This is the end of the HTML body.\r\n";
    char padding_start[] = "<!-- Padding: ";
    char padding_end[] = " -->\r\n";

    size_t body_length = strlen(body);
    size_t ending_length = strlen(ending_string);
    size_t padding_start_length = strlen(padding_start);
    size_t padding_end_length = strlen(padding_end);
    size_t fixed_length = body_length + ending_length + padding_start_length + padding_end_length;
    size_t padding_content_length = TARGET_CONTENT_LENGTH - fixed_length;

    char header[512];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Server: tg\r\n"
             "Date: %s\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %zu\r\n"
             "Last-Modified: %s\r\n"
             "Connection: close\r\n"
             "Accept-Ranges: bytes\r\n"
             "\r\n",
             date_str, TARGET_CONTENT_LENGTH, date_str);

    size_t header_length = strlen(header);
    size_t current_length = 0;

    memcpy(html, header, header_length);
    current_length += header_length;

    memcpy(html + current_length, body, body_length);
    current_length += body_length;

    memcpy(html + current_length, ending_string, ending_length);
    current_length += ending_length;

    if (padding_content_length > 0) {
        memcpy(html + current_length, padding_start, padding_start_length);
        current_length += padding_start_length;

        char random_chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        size_t random_chars_length = strlen(random_chars);
        for (size_t i = 0; i < padding_content_length; i++) {
            html[current_length + i] = random_chars[rand() % random_chars_length];
        }
        current_length += padding_content_length;

        memcpy(html + current_length, padding_end, padding_end_length);
        current_length += padding_end_length;
    }

    html[current_length] = '\0';
    html_len = current_length;
    printf("html len: %d, content: %s\n", strlen(html), html);
}

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
    cli->connect_flag = 0;

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
#if 1
    if (cc_count < cc_cli_count) {
        int i = 0;
        while (i < 1) {
            cc_client_connect();
            i++;
            cc_count++;
        }
    } else {
        static int abc = 0;
        abc++;
        if (abc >= 20) {
            ev_break(EV_A_ EVBREAK_ALL);
        }
    }
#else
    static int abc = 0;
    abc++;
    if (abc >= 200) {
        ev_break(EV_A_ EVBREAK_ALL);
    }
#endif
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
    struct tcp_client *cli = container_of(tcp_client, struct tcp_client, handle);

    cli->write_ptr = html;
    cli->write_sz = html_len;
    if (netbsd_accept(&tcp_server, tcp_client)) {
        printf("Accept tcp client error\n");
        return;
    }
    total_accept_cls ++;
    netbsd_io_start(tcp_client);
}

static void tcp_connect_cb(void *handle, int events) {
    struct netbsd_handle *tcp_client = (struct netbsd_handle *)handle;
    struct tcp_client *cli = container_of(handle, struct tcp_client, handle);

    tcp_client->read_cb = tcp_client_read_cb;
    cli->write_ptr = html;
    cli->write_sz = html_len;

    char *buffer = "1234";
    struct iovec iov = {
        .iov_base = cli->write_ptr,
        .iov_len = strlen(buffer)
    };
    int len = netbsd_write(tcp_client, &iov, 1);
    if (len < 0) {
        printf("netbsd_write failed, close socket");
        netbsd_close(tcp_client);
        return;
    }
    cli->connect_flag = 1;
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
        //printf("read data: %lu: %s\n", iov.iov_len, (char *)iov.iov_base);
        iov.iov_base = cli->write_ptr;;
        iov.iov_len = cli->write_sz;;
        //printf("write data: %lu: %s\n", iov.iov_len, (char *)iov.iov_base);
        int sent = netbsd_write(nh, &iov, 1);
        //printf("sent data: %lu\n", sent);
        if (sent < 0) {
            printf("failed to send: %d\n", (int)sent);
            netbsd_close(nh);
            return;
        }
        cli->write_ptr += sent;
        cli->write_sz -= sent;
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
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    struct tcp_client *cli = container_of(handle, struct tcp_client, handle);

     if (cli->write_sz > 0) {
         struct iovec iov;;
         iov.iov_base = cli->write_ptr;;
         iov.iov_len = cli->write_sz;;
        int sent = netbsd_write(nh, &iov, 1);
        //printf("sent data: %lu\n", sent);
        if (sent < 0) {
            printf("failed to send: %d\n", (int)sent);
            netbsd_close(nh);
            return;
        }
        cli->write_ptr += sent;
        cli->write_sz -= sent;

        if (cli->write_sz == 0) {
            printf("write done on one connection\n");
            netbsd_close(nh);
        }
     }
}
static void tcp_close_cb(void *handle, int events) {
    netbsd_close(handle);
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
    addr.sin_port = htons(80);

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
    generate_html();

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
