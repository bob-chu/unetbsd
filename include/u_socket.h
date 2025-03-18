#ifndef U_SOCKET_H
#define U_SOCKET_H

#include <sys/queue.h>

/* 回调函数类型 */
typedef void (*netbsd_read_cb)(void *handle, int events);
typedef void (*netbsd_write_cb)(void *handle, int error);
typedef void (*netbsd_close_cb)(void *handle);

/* socket 处理结构体 */
struct netbsd_handle {
    struct socket *so;              /* NetBSD socket */
    int is_ipv4;                    /* 是否 IPv4 */
    int type;                       /* socket 类型 (SOCK_STREAM, SOCK_DGRAM) */
    int proto;                      /* 协议 (IPPROTO_TCP, IPPROTO_UDP) */
    netbsd_read_cb read_cb;         /* 读取回调 */
    netbsd_write_cb write_cb;       /* 写入回调 */
    netbsd_close_cb close_cb;       /* 关闭回调 */
    void *data;
    int active;
};

struct netbsd_event {
    struct netbsd_handle *nh;
    int events;
    TAILQ_ENTRY(netbsd_event) next;
};

TAILQ_HEAD(netbsd_event_queue, netbsd_event);

/* socket API */
int netbsd_socket(struct netbsd_handle *nh);
int netbsd_bind(struct netbsd_handle *nh, const struct sockaddr *addr);
int netbsd_listen(struct netbsd_handle *nh, int backlog);
int netbsd_connect(struct netbsd_handle *nh, struct sockaddr *addr);

void netbsd_io_start(struct netbsd_handle *nh);
int netbsd_accept(struct netbsd_handle *nh_server, struct netbsd_handle *nh_client);
int netbsd_close(struct netbsd_handle *nh);

int netbsd_socket_error(struct netbsd_handle *nh);

int netbsd_read(struct netbsd_handle *nh, struct iovec *iov, int iovcnt);
ssize_t netbsd_write(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt);

size_t netbsd_recvfrom(struct netbsd_handle *nh, struct iovec *iov, int iovcnt, struct sockaddr *from);
ssize_t netbsd_sendto(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt, const struct sockaddr *to);

void netbsd_process_event();
#endif
