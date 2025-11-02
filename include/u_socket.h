#ifndef U_SOCKET_H
#define U_SOCKET_H

#include <sys/queue.h>

typedef void (*netbsd_read_cb)(void *handle, int events);
typedef void (*netbsd_write_cb)(void *handle, int events);
typedef void (*netbsd_close_cb)(void *handle, int events);

enum proto_type {
    PROTO_TCP,
    PROTO_UDP,
};

struct netbsd_handle {
    struct socket *so;
    int is_ipv4;
    int type;
    enum proto_type proto;
    netbsd_read_cb read_cb;
    netbsd_write_cb write_cb;
    netbsd_close_cb close_cb;
    void *data;
    int active;
    int is_closing;
    int events;
    int on_event_queue;
};

struct netbsd_event {
    struct netbsd_handle *nh;
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
int netbsd_write(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt);

int netbsd_recvfrom(struct netbsd_handle *nh, struct iovec *iov, int iovcnt, struct sockaddr *from);
int netbsd_sendto(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt, const struct sockaddr *to);

int netbsd_reuseaddr(struct netbsd_handle *nh, const void *optval, socklen_t optlen);
int netbsd_reuseport(struct netbsd_handle *nh, const void *optval, socklen_t optlen);
int netbsd_linger_set(struct netbsd_handle *nh, struct linger *l);

void netbsd_process_event();
#endif
