#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#include <arpa/inet.h> /* htons */
#include <ev.h>
#include <init.h>
#include <netinet/in.h> /* IPPROTO_UDP, struct sockaddr_in, INADDR_ANY */
//#include <openssl/md5.h>
#include <sys/socket.h>
#include <u_if.h>
#include <u_socket.h>

#include "logger.h"
#include "gen_if.h"

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
static struct netbsd_handle udp_client;
static struct netbsd_handle tcp_server;
static struct tcp_client s_tcp_client[MAX_CLIENTS];
static struct tcp_client tcp_curr_client[CURRENT_CLIENTS];

static struct ev_loop *loop;

static int cli_idx = 0;
static int cc_cli_count = 10;
static int read_flag = 0;
static int total_accept_cls = 0;

static void tcp_read_cb(void *handle, int events);
static void tcp_write_cb(void *handle, int events);
static void tcp_close_cb(void *handle, int events);
static void tcp_client_read_cb(void *handle, int events);
static void tcp_connect_cb(void *handle, int events);

#define TARGET_CONTENT_LENGTH 100000

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

static void udp_client_read_cb(void *handle, int events) {
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    char buffer[2048];
    struct iovec iov = {.iov_base = buffer, .iov_len = 2048};
    size_t bytes;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    char ip_str[INET_ADDRSTRLEN];
    uint16_t port;

    bytes = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&from);
    if (bytes > 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&from;
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        port = ntohs(sin->sin_port);
        printf("Received %zu bytes from %s:%u: %.*s\n", bytes, ip_str, port, (int)bytes, (char *)iov.iov_base);
    } else if (bytes == 0) {
        printf("No data received\n");
    } else {
        printf("Read error: %zu\n", bytes);
        netbsd_close(nh);
    }
}

static void udp_client_init() {
    udp_client.is_ipv4 = 1;
    udp_client.proto = PROTO_UDP;
    udp_client.read_cb = udp_client_read_cb;
    udp_client.active = 0;
    int ret = netbsd_socket(&udp_client);
    if (ret) {
        printf("netbsd create socket error: %d\n", ret);
    }
    udp_client.active = 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12346); // Client port

    ret = netbsd_bind(&udp_client, (struct sockaddr *)&addr);
    if (ret) {
        printf("bind error: %d\n", ret);
        netbsd_close(&udp_client);
    }

    netbsd_io_start(&udp_client);
    printf("udp client started\n");

    struct sockaddr_in svr_addr;
    memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.1", &svr_addr.sin_addr);
    svr_addr.sin_port = htons(12345);

    if (netbsd_connect(&udp_client, (struct sockaddr *)&svr_addr)) {
        printf("Can not connect to server\n");
        netbsd_close(&udp_client);
        return;
    }
}

static void send_udp_message(int count) {
    char buffer[128];
    sprintf(buffer, "Hello from client %d", count);

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = strlen(buffer),
    };

    ssize_t sent = netbsd_write(&udp_client, &iov, 1);
    if (sent < 0) {
        printf("Failed to send: %d\n", (int)sent);
    } else {
        printf("Sent %zd bytes\n", sent);
    }
}

static void timer_1s_cb(EV_P_ ev_timer *w, int revents) {
    static int count = 0;
    if (count < 10) {
        send_udp_message(count + 1);
        count++;
    } else {
        ev_break(EV_A_ EVBREAK_ALL);
    }
}

static void idle_cb(struct ev_loop *loop, ev_idle *w, int revents) {
    dpdk_read();
    netbsd_process_event();
}

static void udp_read_cb(void *handle, int events) {
    static int udp_packet_count = 0;
    printf("udp_read_cb called\n");
    struct netbsd_handle *nh = (struct netbsd_handle *)handle;
    char buffer[2048];
    struct iovec iov = {.iov_base = buffer, .iov_len = 2048};
    size_t bytes;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    char ip_str[INET_ADDRSTRLEN];
    uint16_t port;

    bytes = netbsd_recvfrom(nh, &iov, 1, (struct sockaddr *)&from);
    if (bytes > 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&from;
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
        port = ntohs(sin->sin_port);
        printf("Received %zu bytes from %s:%u: %.*s\n", bytes, ip_str, port, (int)bytes, (char *)iov.iov_base);

        iov.iov_len = bytes;
        ssize_t sent = netbsd_sendto(nh, &iov, 1, (struct sockaddr *)&from);
        if (sent < 0) {
            printf("Failed to send: %d\n", (int)sent);
        } else {
            printf("Sent %zd bytes back to %s:%u: %.*s\n", sent, ip_str, port, (int)sent, (char *)iov.iov_base);
            udp_packet_count++;
            if (udp_packet_count >= 10) {
                printf("Received and echoed 10 UDP packets. Exiting.\n");
                //ev_break(loop, EVBREAK_ALL);
            }
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
        printf("Accept tcp client error\n"); fflush(stdout);
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
        .iov_len = cli->write_sz,
    };
    int len = netbsd_write(tcp_client, &iov, 1);
    if (len < 0) {
        printf("netbsd_write failed, error: %d, close socket\n", len); fflush(stdout);
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
        if (cli->write_sz <= 0) {
            return;
        }
        //printf("read data: %lu: %s\n", iov.iov_len, (char *)iov.iov_base);
        iov.iov_base = cli->write_ptr;;
        iov.iov_len = cli->write_sz;;
        //printf("write data: %lu: %s\n", iov.iov_len, (char *)iov.iov_base);
        int sent = netbsd_write(nh, &iov, 1);
        //printf("sent data: %lu\n", sent);
        if (sent < 0) {
            printf("failed to send: %d\n", (int)sent); fflush(stdout);
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
            printf("failed to send: %d\n", (int)sent); fflush(stdout);
            netbsd_close(nh);
            return;
        }
        cli->write_ptr += sent;
        cli->write_sz -= sent;

        if (cli->write_sz == 0) {
            printf("write done on one connection\n"); fflush(stdout);
            netbsd_close(nh);
        }
     }
}
static void tcp_close_cb(void *handle, int events) {
    netbsd_close(handle);
    // printf("tcp close_cb.\n");
}

static void udp_server_init() {
    udp_server.is_ipv4 = 1;
    udp_server.proto = PROTO_UDP;
    udp_server.read_cb = udp_read_cb;
    udp_server.active = 0;
    int ret = netbsd_socket(&udp_server);
    if (ret) {
        printf("netbsd create socket error: %d\n");
    }
    udp_server.active = 1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(12345);

    ret = netbsd_bind(&udp_server, (struct sockaddr *)&addr);
    if (ret) {
        printf("bind error: %d\n");
        netbsd_close(&udp_server);
    }

    netbsd_io_start(&udp_server);
    printf("udp udp_server listening on port 12345\n");
}

static void tcp_server_init() {
    struct sockaddr_in addr;

    tcp_server.is_ipv4 = 1;
    tcp_server.proto = PROTO_TCP;
    tcp_server.read_cb = tcp_read_cb;
    tcp_server.write_cb = tcp_write_cb;
    tcp_server.close_cb = tcp_close_cb;

    if (netbsd_socket(&tcp_server)) {
        printf("Failed to crete tcp server socket.\n"); fflush(stdout);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(80);

    if (netbsd_bind(&tcp_server, (struct sockaddr *)&addr)) {
        printf("TCP server bind addr failed\n"); fflush(stdout);
        netbsd_close(&tcp_server);
        return;
    }

    if (netbsd_listen(&tcp_server, 5)) {
        printf("TCP server listen  failed\n"); fflush(stdout);
        netbsd_close(&tcp_server);
    }

    netbsd_io_start(&tcp_server);

    printf("TCP echo server listening on port 12345\n"); fflush(stdout);
}

int main()
{
    logger_init();
    logger_set_level(LOG_LEVEL_INFO);  // Show all logs above DEBUG
    logger_enable_colors(1);            // Enable colored output

    generate_html();
    char *dpdk_str[] = {
       [0] =  "tt",
       [1] = " -n4",
       [2] =  "-c",
       [3] = "0x3",
       [4] = "-m",
       [5] = "1024",
       [6] = "--no-huge",
       [7] = "--vdev=eth_af_packet0,iface=veth1,blocksz=4096,framesz=2048,framecnt=512,qpairs=1,qdisc_bypass=0",
       [8] = "--proc-type=auto",
       [9] = "--file-prefix=container-veth0",
    };

    netbsd_init();

    dpdk_init(10, dpdk_str);
    open_interface("veth1");

    loop = EV_DEFAULT;
    ev_io tun_read_watcher;
    ev_idle idle_watcher;
    ev_timer timer_10ms_watcher;
    ev_timer timer_1s_watcher;

    ev_timer_init(&timer_10ms_watcher, timer_10ms_cb, 0.01, 0.01);
    ev_timer_start(loop, &timer_10ms_watcher);

    ev_timer_init(&timer_1s_watcher, timer_1s_cb, 1.0, 1.0);
    ev_timer_start(loop, &timer_1s_watcher);

    ev_idle_init(&idle_watcher, idle_cb);
    ev_idle_start(loop, &idle_watcher);

    printf("hello world\n"); fflush(stdout);

    udp_server_init();
    //tcp_server_init();
    //udp_client_init();
    ev_run(loop, 0);

    return 0;
}
