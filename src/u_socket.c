#include "stub.h"
#include "u_socket.h"
#include <sys/malloc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/mbuf.h>

extern struct lwp	*curlwp;

static struct netbsd_event_queue event_queue = TAILQ_HEAD_INITIALIZER(event_queue);

static void soupcall_set(struct socket *so, void *arg,
        void (*so_upcall) (struct socket *, void *, int, int))
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

/* 读取回调处理 */
static void
soupcall_cb(struct socket *so, void *arg, int events, int waitflag)
{
    struct netbsd_handle *nh  = (struct netbsd_handle *)arg;
    struct netbsd_event *ev;
    //container_of

    printf("%s:%d: so: %p, nh: %p, events: %d\n",
            __FUNCTION__, __LINE__, nh->so, nh, events);

#if 1
    ev = malloc(sizeof(*ev), M_TEMP, M_NOWAIT);
    if (ev == NULL) {
        printf("Failed to alloce event.\n");
        return;
    }
    ev->nh = nh;
    ev->events = events;
    TAILQ_INSERT_TAIL(&event_queue, ev, next);

#else
    switch (events) {
            case POLLIN|POLLRDNORM:
                if (nh->read_cb && nh->so) {
                    nh->read_cb(nh, events);
                }
                break;
            case POLLOUT|POLLWRNORM:
                if (nh->write_cb && nh->so) {
                    nh->write_cb(nh->data, nh->so->so_error);
                }
                break;
            case POLLHUP:
                if (nh->close_cb) {
                    nh->close_cb(nh);
                }
                break;
            default:
                break;

        }

#endif
    so->so_rcv.sb_flags |= SB_UPCALL;
    so->so_snd.sb_flags |= SB_UPCALL;
}

void
netbsd_process_event()
{
    struct netbsd_event *ev;
    while ((ev = TAILQ_FIRST(&event_queue)) != NULL) {
        struct netbsd_handle *nh = ev->nh;
        int events = ev->events;
        printf("%s:%d: so: %p, nh: %p, events: %d\n",
                __FUNCTION__, __LINE__, nh->so, nh, events);
        TAILQ_REMOVE(&event_queue, ev, next);
        switch (events) {
            case POLLIN|POLLRDNORM:
                if (nh->read_cb && nh->so) {
                    printf("CCB: 11111: nh: %p\n", nh);
                    nh->read_cb(nh, events);
                }
                break;
            case POLLOUT|POLLWRNORM:
                if (nh->write_cb && nh->so) {
                    nh->write_cb(nh->data, nh->so->so_error);
                }
                break;
            case POLLHUP:
                if (nh->close_cb) {
                    nh->close_cb(nh);
                }
                break;
            default:
                break;

        }
        free(ev, M_TEMP);
    }
}

/* 创建 socket */
int
netbsd_socket(struct netbsd_handle *nh)
{
    int error;

    error = socreate(nh->is_ipv4 ? AF_INET : AF_INET6, &nh->so, nh->type, nh->proto, curlwp, NULL);
    return error;
}

void
netbsd_io_start(struct netbsd_handle *nh)
{
    soupcall_set(nh->so, nh, soupcall_cb);
}

/* 绑定地址 */
int
netbsd_bind(struct netbsd_handle *nh, const struct sockaddr *addr)
{
    struct sockaddr_storage sa;
    int len = nh->is_ipv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

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

/* 开始监听 */
int
netbsd_listen(struct netbsd_handle *nh, int backlog)
{
    return solisten(nh->so, backlog, curlwp);
}

static void
sobuf_reset(struct sockbuf *sb)
{
struct mbuf *m, *n;

    /* 释放所有 mbuf */
    m = sb->sb_mb;
    while (m != NULL) {
        n = m->m_next;
        m_free(m);
        m = n;
    }
    sb->sb_mb = NULL;    /* 清空 mbuf 链表 */
    sb->sb_cc = 0;       /* 已用字节数 */
    sb->sb_hiwat = 0;    /* 高水位标记 */
    sb->sb_mbcnt = 0;    /* mbuf 计数 */
    sb->sb_flags = 0;    /* 清空标志 */
    printf("CCB: sockbuf reset, sb=%p\n", sb);
}

int
netbsd_accept(struct netbsd_handle *nh_server, struct netbsd_handle *nh_client)
{
    struct socket *so, *so2, *new_so;
    struct sockaddr sa;
    int error;

    so = nh_server->so;

    if ((so->so_options & SO_ACCEPTCONN) == 0) {
        return EINVAL;
    }

    /* 检查队列是否为空 */
    if (TAILQ_EMPTY(&so->so_q)) {
        if (so->so_state & SS_NBIO) {
            return EWOULDBLOCK;
        }
        return EAGAIN; /* 或等待，视需求 */
    }

    so2 = TAILQ_FIRST(&so->so_q);
    if (soqremque(so2, 1) == 0) {
        panic("netbsd_accept: soqremque failed");
    }

    error = soaccept(so, &sa);
    if (error) {
        return error;
    }
#if 0
    /* 创建新的 socket，而不是重用 so2 */
    error = socreate(nh_client->is_ipv4 ? AF_INET : AF_INET6, &new_so, nh_client->type,
            nh_client->proto, curlwp, NULL);
    if (error) {
        printf("CCB: socreate failed: %d\n", error);
        soclose(so2);
        return error;
    }

    new_so->so_state = so2->so_state;
    new_so->so_rcv = so2->so_rcv;
    new_so->so_snd = so2->so_snd;
    new_so->so_q = so2->so_q;
    new_so->so_q0 = so2->so_q0;

    /* 重置旧 socket 的缓冲区并关闭 */
    so2->so_rcv.sb_mb = NULL;
    so2->so_snd.sb_mb = NULL;
    soclose(so2);

    /* 设置新 socket */
    new_so->so_state = SS_ISCONNECTED;
    new_so->so_rcv.sb_hiwat = 65536;
    new_so->so_snd.sb_hiwat = 65536;

    /* 设置新 socket 的 upcall */
    new_so->so_upcall = soupcall_cb;
    new_so->so_upcallarg = nh_client;
    nh_client->so = new_so;
    //nh_client->so = so2;
    printf("CCB: accepted socket %p, so_rcv.sb_cc=%u\n", new_so, new_so->so_rcv.sb_cc);
    if (new_so->so_rcv.sb_cc > 0) {
        soupcall_cb(new_so, nh_client, POLLIN|POLLRDNORM, 0);
    }
#else
    nh_client->so = so2;
    netbsd_io_start(nh_client);
    printf("CCB: accepted socket %p, so_rcv.sb_cc=%u, nh: %p\n",
            so2, so2->so_rcv.sb_cc, nh_client);
    if (so2->so_rcv.sb_cc > 0) {
        soupcall_cb(so2, nh_client, POLLIN|POLLRDNORM, 0);
    }
#endif
    return 0;
}

/* 发起连接 */
int
netbsd_connect(struct netbsd_handle *nh, struct sockaddr *addr)
{
    struct sockaddr_storage sa;
    int len = nh->is_ipv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    memcpy(&sa, addr, len);
    if (nh->is_ipv4) {
        ((struct sockaddr_in *)&sa)->sin_family = AF_INET;
        ((struct sockaddr_in *)&sa)->sin_len = len;
    } else {
        ((struct sockaddr_in6 *)&sa)->sin6_family = AF_INET6;
        ((struct sockaddr_in6 *)&sa)->sin6_len = len;
    }

    return soconnect(nh->so, (struct sockaddr *)&sa, curlwp);
}

/* 关闭 socket */
int
netbsd_close(struct netbsd_handle *nh)
{
    if (nh->so) {
        soupcall_clear(nh->so);
        soclose(nh->so);
        nh->so = NULL;
    }
    return 0;
}

/* 获取 socket 错误 */
int
netbsd_socket_error(struct netbsd_handle *nh)
{
    return nh->so ? nh->so->so_error : 0;
}

static size_t so_read(struct netbsd_handle *nh, struct iovec *iov, int iovcnt, struct sockaddr *from)
{
    struct uio uio;             /* 用户 I/O 结构 */
    ssize_t bytes, total;              /* 可读取字节数 */
    int error;                  /* 错误码 */
    int flags = MSG_DONTWAIT;   /* 非阻塞读取 */
    struct sockaddr_storage sa;
    struct mbuf *addr_mbuf = NULL;

    struct socket *so = nh->so;

    /* 检查参数 */
    if (so == NULL || iov == NULL || iovcnt <= 0) {
        printf("CCB: ERRRRRRRRRRRRRRRRRRRRRRRRR\n");
        printf("CCB: so: %p, iov: %p, iovcnt: %d\n",
                so, iov, iovcnt);
        return -EINVAL;
    }

    /* 初始化 uio */
    uio.uio_iov = iov;
    uio.uio_iovcnt = iovcnt;
    uio.uio_offset = 0;
    uio.uio_resid = 0;
    uio.uio_rw = UIO_READ;
    for (int i = 0; i < iovcnt; i++) {
        if (iov[i].iov_len < 0) {
            return -EINVAL;
        }
        uio.uio_resid += iov[i].iov_len; /* 计算总缓冲区大小 */
    }

    /* 获取接收缓冲区数据量 */
    bytes = so->so_rcv.sb_cc;
    total = uio.uio_resid;
    if (total == 0) {
        return -1; /* 无数据 */
    }

    /* 限制读取量不超过缓冲区 */
    //if (total > uio.uio_resid) {
    //    total = uio.uio_resid;
    //}

    /* 调用 soreceive 读取数据 */
    //error = soreceive(so, NULL, &uio, NULL, NULL, &flags);
    error = soreceive(so, from ? &addr_mbuf: NULL, &uio, NULL, NULL, &flags);
    if (error) {
        return -error; /* 返回负值表示错误，如 -EAGAIN */
    }

    if (from && addr_mbuf) {
        int len = MIN(addr_mbuf->m_len, sizeof(struct sockaddr_storage));
        m_copydata(addr_mbuf, 0, len, (char *)&sa);
        memcpy(from, &sa, len);
        m_freem(addr_mbuf);
    } else if (addr_mbuf) {
        m_freem(addr_mbuf);
    }

    /* 计算实际读取字节数 */
    bytes = total - uio.uio_resid;

    return bytes;
}


int netbsd_read(struct netbsd_handle *nh, struct iovec *iov, int iovcnt)
{
    return so_read(nh, iov, iovcnt, NULL);
}

size_t
netbsd_recvfrom(struct netbsd_handle *nh, struct iovec *iov, int iovcnt, struct sockaddr *from)
{
    return so_read(nh, iov, iovcnt, from);
}

static ssize_t
so_send(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt, const struct sockaddr *to)
{
    struct uio uio;
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

    /* 对于 UDP，未连接时需要 to 参数；对于 TCP，忽略 to（依赖 SS_ISCONNECTED） */
    error = sosend(so, to ? (struct sockaddr *)to : NULL, &uio, NULL, NULL, flags, curlwp);
    if (error) {
        return -error;
    }

    bytes = bytes - uio.uio_resid;
    return bytes;
}

ssize_t
netbsd_write(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt)
{
    return so_send(nh, iov, iovcnt, NULL);
}

ssize_t
netbsd_sendto(struct netbsd_handle *nh, const struct iovec *iov, int iovcnt, const struct sockaddr *to)
{
    return so_send(nh, iov, iovcnt, to);
}


