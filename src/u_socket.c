#include "stub.h"
#include "u_socket.h"
#include "u_softint.h"
#include "u_fd.h"
#include <sys/malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
    so->so_upcallarg = NULL;
}

static void enqueue_event(struct netbsd_handle *nh, int events)
{
#if 0
    printf("enqueue_event: nh=%p, so=%p, events=%s%s%s%s%s%s%s%s\n",
           (void *)nh, (void *)nh->so,
           (events & POLLIN) ? "POLLIN " : "",
           (events & POLLOUT) ? "POLLOUT " : "",
           (events & POLLRDNORM) ? "POLLRDNORM " : "",
           (events & POLLWRNORM) ? "POLLWRNORM " : "",
           (events & POLLERR) ? "POLLERR " : "",
           (events & POLLHUP) ? "POLLHUP " : "",
           (events & POLLNVAL) ? "POLLNVAL " : "",
           (events & POLLPRI) ? "POLLPRI " : "");
#endif
    struct netbsd_event *ev;

    // If the handle is already closing or socket is NULL, don't enqueue new events unless it's a close event
    if ((nh->is_closing || nh->so == NULL) && !(events & POLLHUP)) {
        return;
    }

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
    //so->so_rcv.sb_flags |= SB_UPCALL;
    //so->so_snd.sb_flags |= SB_UPCALL;
}

void netbsd_process_event()
{
    struct netbsd_event *ev;
    int count = 16;
    while ((ev = TAILQ_FIRST(&event_queue)) != NULL && count-- > 0) {
        struct netbsd_handle *nh = ev->nh;
        int events;
        TAILQ_REMOVE(&event_queue, ev, next);
        nh->on_event_queue = 0;
        events = nh->events;
        nh->events = 0;
#if 0
        printf("netbsd_process_event: nh=%p, so=%p, events=%s%s%s%s%s%s%s%s\n",
               (void *)nh, (void *)nh->so,
               (events & POLLIN) ? "POLLIN " : "",
               (events & POLLOUT) ? "POLLOUT " : "",
               (events & POLLRDNORM) ? "POLLRDNORM " : "",
               (events & POLLWRNORM) ? "POLLWRNORM " : "",
               (events & POLLERR) ? "POLLERR " : "",
               (events & POLLHUP) ? "POLLHUP " : "",
               (events & POLLNVAL) ? "POLLNVAL " : "",
               (events & POLLPRI) ? "POLLPRI " : "");
        printf("process event on nh: %p\n", nh);
#endif
        // If the handle is already closing, skip further processing of read/write events
        // but still allow close_cb to be called if POLLHUP is set.
        if (nh->is_closing && !(events & POLLHUP)) {
            free(ev, M_TEMP);
            continue;
        }

        if (events & (POLLIN | POLLRDNORM)) {
            if (nh->read_cb && nh->so) { // Check nh->so before calling read_cb
                nh->read_cb(nh, events);
            }
        }
        if (events & (POLLOUT | POLLWRNORM)) {
            if (nh->write_cb && nh->so) { // Check nh->so before calling write_cb
                nh->write_cb(nh, events);
            }
        }
        // Prioritize close events
        if (events & POLLHUP) {
            if (nh->close_cb) {
                nh->close_cb(nh, events);
            }
            // After close_cb, the nh might be freed, so we must not access it further.
            free(ev, M_TEMP);
            continue;
        }

        // Check for socket error state before processing read/write events
        if (nh->so && nh->so->so_error != 0) {
            //printf("Socket in error state during event processing: nh:%p, so:%p, error:%d\n", nh, nh->so, nh->so->so_error);
            nh->is_closing = 1;
            enqueue_event(nh, POLLHUP); // Trigger close event
            // Ensure the socket is closed if not already closed
            if (nh->so) {
                soupcall_clear(nh->so); // Clear callbacks to prevent further events
                soclose(nh->so); // Explicitly close the socket
                nh->so = NULL;
            }
            free(ev, M_TEMP);
            continue;
        }


        free(ev, M_TEMP);
    }
}

void netbsd_loop()
{
    softint_run();
    netbsd_process_event();
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
        return error;
    }

    int optval = 1;
    struct sockopt sopt;
    bzero(&sopt, sizeof(sopt));
    sopt.sopt_level = SOL_SOCKET;
    sopt.sopt_name = SO_DEBUG;
    sopt.sopt_data = &optval;
    sopt.sopt_size = sizeof(optval);
    sosetopt(nh->so, &sopt);

    nh->fd = u_fd_alloc(nh);
    if (nh->fd < 0) {
        soclose(nh->so);
        nh->so = NULL;
        return -1;
    }
    return 0;
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
    netbsd_io_start(nh_client);
    if (so2->so_rcv.sb_cc > 0) {
        soupcall_cb(so2, nh_client, POLLIN | POLLRDNORM, 0);
    }
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
    if (ret != 0) {
        printf("soconnect failed with error: %d\n", ret);
    }
    /* enable debug */
    //nh->so->so_options |= SO_DEBUG;

    return ret;
}

int netbsd_close(struct netbsd_handle *nh)
{
    if (nh->so) {
        nh->is_closing = 1; // Set the flag before closing the socket
        
        // Clear any upcall handlers to prevent further events
        soupcall_clear(nh->so);
        
        // Close the socket
        soclose(nh->so);
        nh->so = NULL;
        
        // Free the file descriptor
        u_fd_free(nh->fd);
        nh->fd = -1;

        // Remove any pending events for this handle from the queue
        struct netbsd_event *ev, *tmp;
        TAILQ_FOREACH_SAFE(ev, &event_queue, next, tmp) {
            if (ev->nh == nh) {
                TAILQ_REMOVE(&event_queue, ev, next);
                nh->on_event_queue = 0;
                nh->events = 0;
                free(ev, M_TEMP);
            }
        }
        
        // Enqueue a close event to notify the application
        enqueue_event(nh, POLLHUP);
        //if (nh->close_cb) {
        //    nh->close_cb(nh, POLLHUP);
        //}
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
        printf("HHHHHHHHHHHHHHHHHHHHH, return -1 ??????\n");
        return -1;
    }

    error = soreceive(so, from ? &addr_mbuf : NULL, &uio, NULL, NULL, &flags);
    if (error) {
        //printf("soreceiver return %d\n", error);
        return -error; /* return error, like -EAGAIN */
    }
    if (so->so_state & SS_CANTRCVMORE) {
        /* EOF notify*/
        return -EPIPE;
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
    if (nh->is_closing || nh->so == NULL || nh->so->so_error != 0) {
        if (nh->so && nh->so->so_error != 0) {
            int error = nh->so->so_error;
            enqueue_event(nh, POLLHUP); // Ensure close event is enqueued
            nh->is_closing = 1; // Mark as closing to prevent further operations
            return -error;
        }
        return -EINVAL;
    }
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

    // Check if the handle or socket is NULL or if the socket is in error state or closed
    if (so == NULL || iov == NULL || iovcnt <= 0 || nh->is_closing || so->so_error != 0) {
        if (so && so->so_error != 0) {
            int error = so->so_error;
            printf("Failed to write to socket due to error state: nh:%p, so: %p, (errno: %d)\n", nh, so, error);
            enqueue_event(nh, POLLHUP); // Ensure close event is enqueued
            nh->is_closing = 1; // Mark as closing to prevent further operations
            return -error; // Return the specific error if available
        }
        return -EINVAL; // Otherwise return a generic invalid argument error
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
        if (error == EWOULDBLOCK) {
            return 0;
        }
        return -error;
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
    sopt.sopt_name = SO_REUSEPORT;
    error = sosetopt(so, &sopt);
    if (error) {
        printf("netbsd_reuseport failed: level=%d, optname=%d, error=%d\n",
                sopt.sopt_level, sopt.sopt_name, error);
    }

    return error;
}

int netbsd_nodelay(struct netbsd_handle *nh, const void *optval, socklen_t optlen)
{
    struct socket *so = nh->so;
    if (so == NULL || optval == NULL || optlen <= 0) {
        return EINVAL;
    }

    struct sockopt sopt;
    bzero(&sopt, sizeof(sopt));
    sopt.sopt_level = IPPROTO_TCP;
    sopt.sopt_name = TCP_NODELAY;
    sopt.sopt_data = (void *)optval;
    sopt.sopt_size = optlen;

    int error = sosetopt(so, &sopt);
    if (error) {
        printf("netbsd_nodelay failed: level=%d, optname=%d, error=%d\n",
                sopt.sopt_level, sopt.sopt_name, error);
    }

    return error;
}
