#include "stub.h"
#include "u_socket.h"
#include <sys/malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/mbuf.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/uio.h>

extern struct lwp *curlwp;

static struct netbsd_event_queue event_queue =
TAILQ_HEAD_INITIALIZER(event_queue);

static void soupcall_set(struct socket *so, void *arg,
    void (*so_upcall)(struct socket *, void *, int, int))
{
    so->so_upcallarg = arg;
    so->so_upcall = so_upcall;
    so->so_rcv.sb_flags |= SB_UPCALL;
    so->so_snd.sb_flags |= SB_UPCALL;
}

static void soupcall_clear(struct socket *so)
{
    so->so_rcv.sb_flags &= ~SB_UPCALL;
    so->so_snd.sb_flags &= ~SB_UPCALL;
    so->so_upcallarg = NULL;
    so->so_upcall = NULL;
}

static void enqueue_event(struct netbsd_handle *nh, int events)
{
    struct netbsd_event *ev;

    nh->events |= events;

    if (nh->on_event_queue) {
        return;
    }

    ev = malloc(sizeof(*ev), M_TEMP, M_NOWAIT);
    if (ev == NULL) {
        printf("Failed to allocate event.\n");
        return;
    }
    ev->nh = nh;
    nh->on_event_queue = 1;
    TAILQ_INSERT_TAIL(&event_queue, ev, next);
}

static void soupcall_cb(struct socket *so, void *arg, int events, int waitflag)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)arg;

    enqueue_event(nh, events);
    so->so_rcv.sb_flags |= SB_UPCALL;
    so->so_snd.sb_flags |= SB_UPCALL;
}

void netbsd_process_event()
{
    struct netbsd_event *ev;
    while ((ev = TAILQ_FIRST(&event_queue)) != NULL) {
        struct netbsd_handle *nh = ev->nh;
        int events;
        TAILQ_REMOVE(&event_queue, ev, next);
        nh->on_event_queue = 0;
        events = nh->events;
        nh->events = 0;

        if (events & (POLLIN | POLLRDNORM)) {
            if (nh->read_cb && nh->so) {
                nh->read_cb(nh, events);
            }
        }
        if (events & (POLLOUT | POLLWRNORM)) {
            if (nh->write_cb && nh->so) {
                nh->write_cb(nh, nh->so->so_error);
            }
        }
        if (events & POLLHUP) {
            if (nh->so && nh->close_cb) {
                nh->close_cb(nh, events);
            }
        }
        free(ev, M_TEMP);
    }
}

int netbsd_socket(struct netbsd_handle *nh)
{
    int error;
    int type, proto;

    if (nh->proto == PROTO_TCP) {
        proto = IPPROTO_TCP;
        type = SOCK_STREAM;
    } else if (nh->proto == PROTO_UDP) {
        proto = IPPROTO_UDP;
        type = SOCK_DGRAM;
    } else {
        return -1;
    }
    error = socreate(nh->is_ipv4 ? AF_INET : AF_INET6, &nh->so, type,
            proto, curlwp, NULL);
    if (error) {
        printf("socreate failed with error: %d\n", error);
    }
    return error;
}

void netbsd_io_start(struct netbsd_handle *nh)
{
    soupcall_set(nh->so, nh, soupcall_cb);
}

int netbsd_bind(struct netbsd_handle *nh, const struct sockaddr *addr)
{
    struct sockaddr_storage sa;
    int len =
        nh->is_ipv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    memcpy(&sa, addr, len);
    if (nh->is_ipv4) {
        ((struct sockaddr_in *)&sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)&sa)->sin_len = len;
    } else {
        ((struct sockaddr_in6 *)&sa)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&sa)->sin6_len = len;
    }

    return sobind(nh->so, (struct sockaddr *)&sa, curlwp);
}

int netbsd_listen(struct netbsd_handle *nh, int backlog)
{
    return solisten(nh->so, backlog, curlwp);
}

int netbsd_accept(struct netbsd_handle *nh_server,
        struct netbsd_handle *nh_client)
{
    struct socket *so, *so2, *new_so;
    struct sockaddr sa;
    int error;

    so = nh_server->so;

    if ((so->so_options & SO_ACCEPTCONN) == 0) {
        return EINVAL;
    }

    if (TAILQ_EMPTY(&so->so_q)) {
        if (so->so_state & SS_NBIO) {
            return EWOULDBLOCK;
        }
        return EAGAIN;
    }

    so2 = TAILQ_FIRST(&so->so_q);
    if (soqremque(so2, 1) == 0) {
        return EAGAIN; // Avoid panic, just return and try again
    }

    error = soaccept(so, &sa);
    if (error) {
        return error;
    }
    nh_client->so = so2;
    /*
    netbsd_io_start(nh_client);
    if (so2->so_rcv.sb_cc > 0) {
        soupcall_cb(so2, nh_client, POLLIN | POLLRDNORM, 0);
    }
    */
    return 0;
}

int netbsd_connect(struct netbsd_handle *nh, struct sockaddr *addr)
{
    struct sockaddr_storage sa;
    int len =
        nh->is_ipv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    memcpy(&sa, addr, len);
    if (nh->is_ipv4) {
        ((struct sockaddr_in *)&sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)&sa)->sin_len = len;
    } else {
        ((struct sockaddr_in6 *)&sa)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&sa)->sin6_len = len;
    }

    int ret = soconnect(nh->so, (struct sockaddr *)&sa, curlwp);
    /* enable debug */
    //nh->so->so_options |= SO_DEBUG;

    return ret;
}

int netbsd_close(struct netbsd_handle *nh)
{
    if (nh->so) {
        soupcall_clear(nh->so);
        soclose(nh->so);
        nh->so = NULL;
        enqueue_event(nh, POLLHUP);
    }
    return 0;
}

int netbsd_socket_error(struct netbsd_handle *nh)
{
    return nh->so ? nh->so->so_error : 0;
}

static int so_read(struct netbsd_handle *nh, struct iovec *iov, int iovcnt,
        struct sockaddr *from)
{
    struct uio uio;
    int total;
    int error;
    int flags = MSG_DONTWAIT;
    struct sockaddr_storage sa;
    struct mbuf *addr_mbuf = NULL;

    struct socket *so = nh->so;

    if (so == NULL || iov == NULL || iovcnt <= 0) {
        return -EINVAL;
    }

    uio.uio_iov = iov;
    uio.uio_iovcnt = iovcnt;
    uio.uio_offset = 0;
    uio.uio_resid = 0;
    uio.uio_rw = UIO_READ;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len < 0) {
            return -EINVAL;
        }
        uio.uio_resid += iov[i].iov_len;
    }

    total = uio.uio_resid;
    if (total == 0) {
        return -1;
    }

    error = soreceive(so, from ? &addr_mbuf : NULL, &uio, NULL, NULL, &flags);
    if (error) {
        return -error; /* return error, like -EAGAIN */
    }
    if (so->so_state & SS_CANTRCVMORE) {
        /* EOF notify*/
        return -1;
    }
    total -= uio.uio_resid;
    if (from && addr_mbuf) {
        int len = MIN(addr_mbuf->m_len, sizeof(struct sockaddr_storage));
        m_copydata(addr_mbuf, 0, len, (char *)&sa);
        memcpy(from, &sa, len);
        m_freem(addr_mbuf);
    } else if (addr_mbuf) {
        m_freem(addr_mbuf);
    }

    return total;
}

int netbsd_read(struct netbsd_handle *nh, struct iovec *iov, int iovcnt)
{
    return so_read(nh, iov, iovcnt, NULL);
}

int netbsd_recvfrom(struct netbsd_handle *nh, struct iovec *iov, int iovcnt,
        struct sockaddr *from)
{
    return so_read(nh, iov, iovcnt, from);
}

static ssize_t so_send(struct netbsd_handle *nh, const struct iovec *iov,
        int iovcnt, const struct sockaddr *to)
{
    struct uio uio = {0};
    ssize_t bytes = 0;
    int error;
    int flags = MSG_NBIO;
    struct socket *so = nh->so;

    if (so == NULL || iov == NULL || iovcnt <= 0) {
        return -EINVAL;
    }

    uio.uio_iov = (struct iovec *)iov;
    uio.uio_iovcnt = iovcnt;
    uio.uio_offset = 0;
    uio.uio_resid = 0;
    uio.uio_rw = UIO_WRITE;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len < 0) {
            return -EINVAL;
        }
        uio.uio_resid += iov[i].iov_len;
    }
    bytes = uio.uio_resid;

    if (so->so_state & SS_CANTSENDMORE) {
        return -EPIPE;
    }

    error = sosend(so, to ? (struct sockaddr *)to : NULL, &uio, NULL, NULL, flags,
            curlwp);
    if (error) {
        if (error != EWOULDBLOCK) {
            return -error;
        }
    }

    bytes = bytes - uio.uio_resid;
    return bytes;
}

int netbsd_write(struct netbsd_handle *nh, const struct iovec *iov,
        int iovcnt)
{
    return so_send(nh, iov, iovcnt, NULL);
}

int netbsd_sendto(struct netbsd_handle *nh, const struct iovec *iov,
        int iovcnt, const struct sockaddr *to)
{
    return so_send(nh, iov, iovcnt, to);
}

int netbsd_reuseaddr(struct netbsd_handle *nh, const void *optval, socklen_t optlen)
{
    struct socket *so = nh->so;
    if (so == NULL || optval == NULL || optlen <= 0) {
        return EINVAL;
    }

    struct sockopt sopt;
    bzero(&sopt, sizeof(sopt));
    sopt.sopt_level = SOL_SOCKET;
    sopt.sopt_name = SO_REUSEADDR;
    sopt.sopt_data = (void *)optval;
    sopt.sopt_size = optlen;

    int error = sosetopt(so, &sopt);
    if (error) {
        printf("netbsd_reuseaddr failed: level=%d, optname=%d, error=%d\n",
                sopt.sopt_level, sopt.sopt_name, error);
    }
    return error;
}
