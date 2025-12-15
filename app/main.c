#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>

#include <arpa/inet.h> /* htons, inet_pton */
#include <ev.h>
#include <init.h>
#include <netinet/in.h> /* IPPROTO_UDP, INADDR_ANY, IN6ADDR_ANY_INIT */
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
    int flag; /* 0: closed */
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

#define TARGET_CONTENT_LENGTH 700

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
                  "<a href=\"http://unetstack.com/\">unetstack.com</a>.</p>\r\n"
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
             "Content-Length: %u\r\n"
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
    printf("html len: %ld, content: %s\n", strlen(html), html);
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
    nh->is_ipv4 = 0; /* Set to 0 for IPv6; change to 1 for IPv4 if needed */
    nh->proto = PROTO_TCP;
    cli->connect_flag = 0;
    cli->flag = 0;

    if (netbsd_socket(nh) < 0) {
        printf("Can not open socket.\n");
        return;
    }
    int optval = 1;
    if (netbsd_nodelay(nh, &optval, sizeof(optval))) {
        printf("Set nodelay option failed.\n");
    }
    if (netbsd_reuseaddr(nh, &optval, sizeof(optval))) {
        printf("Set reuseaddr option failed.\n");
        netbsd_close(nh);
        return;
    }

    /* IPv6 addresses for client and server */
    const char *ip_str = "2001:db8::2"; /* Client IPv6 address */
    const char *server_str = "2001:db8::1"; /* Server IPv6 address */
    struct sockaddr_storage cli_addr, svr_addr;
    struct sockaddr_in6 *cli_addr6 = (struct sockaddr_in6 *)&cli_addr;
    struct sockaddr_in6 *svr_addr6 = (struct sockaddr_in6 *)&svr_addr;

    memset(&cli_addr, 0, sizeof(cli_addr));
    cli_addr6->sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, ip_str, &cli_addr6->sin6_addr) != 1) {
        printf("Invalid client IPv6 address: %s\n", ip_str);
        netbsd_close(nh);
        return;
    }
    cli_addr6->sin6_port = htons(local_port++);

    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr6->sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, server_str, &svr_addr6->sin6_addr) != 1) {
        printf("Invalid server IPv6 address: %s\n", server_str);
        netbsd_close(nh);
        return;
    }
    svr_addr6->sin6_port = htons(PORT);

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
    tcp_client->is_ipv4 = 0; /* Set to 0 for IPv6 */
    struct tcp_client *cli = container_of(tcp_client, struct tcp_client, handle);

    cli->write_ptr = html;
    cli->write_sz = html_len;
    if (netbsd_accept(&tcp_server, tcp_client)) {
        printf("Accept tcp client error\n");
        return;
    }
    int optval = 1;
    if (netbsd_nodelay(tcp_client, &optval, sizeof(optval))) {
        printf("Set nodelay option failed.\n");
    }
    total_accept_cls++;
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
        .iov_base = buffer,
        .iov_len = strlen(buffer),
    };
    int len = netbsd_write(tcp_client, &iov, 1);
    if (len < 0) {
        printf("netbsd_write failed, close socket\n");
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
    if (cli->connect_flag == 0) return;

    bytes = netbsd_read(nh, &iov, 1);
    if (bytes > 0) {
        if (cli->write_sz > 0) {
            iov.iov_base = cli->write_ptr;
            iov.iov_len = cli->write_sz;
            int sent = netbsd_write(nh, &iov, 1);
            if (sent < 0) {
                printf("failed to send: %d\n", (int)sent);
                netbsd_close(nh);
                return;
            }
            cli->write_ptr += sent;
            cli->write_sz -= sent;
        } else {
            netbsd_close(nh);
            cli->connect_flag = 0;
        }
    } else {
        cli->connect_flag = 0;
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

    if (cli->connect_flag == 0) return;
    if (cli->write_sz > 0) {
        struct iovec iov;
        iov.iov_base = cli->write_ptr;
        iov.iov_len = cli->write_sz;
        int sent = netbsd_write(nh, &iov, 1);
        if (sent < 0) {
            printf("failed to send: %d\n", (int)sent);
            cli->connect_flag = 0;
            netbsd_close(nh);
            return;
        }
        cli->write_ptr += sent;
        cli->write_sz -= sent;
        /*
        if (cli->write_sz == 0) {
            printf("write done on one connection\n");
            netbsd_close(nh);
        }
        */
    }
}

static void tcp_close_cb(void *handle, int events) {
    struct tcp_client *cli = container_of(handle, struct tcp_client, handle);
    cli->connect_flag = 0;
}

static void udp_server_init() {
    udp_server.is_ipv4 = 0; /* Use IPv6 */
    udp_server.proto = PROTO_UDP;
    udp_server.read_cb = udp_read_cb;
    udp_server.active = 0;
    int ret = netbsd_socket(&udp_server);
    if (ret) {
        printf("netbsd create socket error: %d\n", ret);
        return;
    }
    udp_server.active = 1;

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(PORT);

    ret = netbsd_bind(&udp_server, (struct sockaddr *)&addr);
    if (ret) {
        printf("bind error: %d\n", ret);
        netbsd_close(&udp_server);
        return;
    }

    netbsd_io_start(&udp_server);
    printf("UDP server listening on port %d (IPv6)\n", PORT);
}

static void tcp_server_init() {
    struct sockaddr_in6 addr;

    tcp_server.is_ipv4 = 0; /* Use IPv6 */
    tcp_server.proto = PROTO_TCP;
    tcp_server.read_cb = tcp_read_cb;
    tcp_server.write_cb = tcp_write_cb;
    tcp_server.close_cb = tcp_close_cb;

    if (netbsd_socket(&tcp_server)) {
        printf("Failed to create tcp server socket.\n");
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(80);

    if (netbsd_bind(&tcp_server, (struct sockaddr *)&addr)) {
        printf("TCP server bind addr failed\n");
        netbsd_close(&tcp_server);
        return;
    }

    if (netbsd_listen(&tcp_server, 5)) {
        printf("TCP server listen failed\n");
        netbsd_close(&tcp_server);
        return;
    }

    netbsd_io_start(&tcp_server);
    printf("TCP server listening on port 80 (IPv6)\n");
}

int main(int argc, char *argv[]) { struct ev_loop *g_main_loop = EV_DEFAULT;
    int tun_fd = -1;
    generate_html();

    netbsd_init();
    tun_fd = open_af_packet();
    if (tun_fd < 0) {
        printf("Can not open tun device\n");
        return -1;
    }

    struct ev_loop *loop = EV_DEFAULT;
    ev_io tun_read_watcher;
    ev_idle idle_watcher;
    ev_timer timer_10ms_watcher;
    ev_timer timer_1s_watcher;

    ev_io_init(&tun_read_watcher, tun_read_cb, tun_fd, EV_READ);
    ev_io_start(loop, &tun_read_watcher);

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(loop, &timer_10ms_watcher);

    ev_timer_init(&timer_1s_watcher, timer_1s_cb, 1.0, 1.0);
    ev_timer_start(loop, &timer_1s_watcher);

    ev_idle_init(&idle_watcher, idle_cb);
    ev_idle_start(loop, &idle_watcher);

    printf("hello world\n");
    udp_server_init();
    tcp_server_init();
    ev_run(loop, 0);

    close_af_packet();
    free(html);
    return 0;
}
