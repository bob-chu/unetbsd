#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include "u_socket.h"

/*
 * This file is compiled with normal host flags (no -D_KERNEL).
 * It translates internal negative error codes from _u_ functions
 * into the real host errno and returns -1.
 */

static int wrap(int ret) {
    if (ret < 0) {
        errno = -ret;
        return -1;
    }
    return ret;
}

static ssize_t wrap_ssize(ssize_t ret) {
    if (ret < 0) {
        errno = (int)(-ret);
        return -1;
    }
    return ret;
}

int u_socket(int domain, int type, int protocol) {
    return wrap(_u_socket(domain, type, protocol));
}

int u_bind(int s, const struct sockaddr *name, socklen_t namelen) {
    return wrap(_u_bind(s, name, namelen));
}

int u_listen(int s, int backlog) {
    return wrap(_u_listen(s, backlog));
}

int u_accept(int s, struct sockaddr *name, socklen_t *namelen) {
    return wrap(_u_accept(s, name, namelen));
}

int u_connect(int s, const struct sockaddr *name, socklen_t namelen) {
    return wrap(_u_connect(s, name, namelen));
}

ssize_t u_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen) {
    return wrap_ssize(_u_recvfrom(s, buf, len, flags, from, fromlen));
}

ssize_t u_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
    return wrap_ssize(_u_sendto(s, buf, len, flags, to, tolen));
}

int u_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen) {
    return wrap(_u_setsockopt(s, level, optname, optval, optlen));
}

int u_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen) {
    return wrap(_u_getsockopt(s, level, optname, optval, optlen));
}

int u_close(int fd) {
    return wrap(_u_close(fd));
}

int u_getpeername(int s, struct sockaddr *asa, socklen_t *alen) {
    return wrap(_u_getpeername(s, asa, alen));
}

int u_getsockname(int s, struct sockaddr *asa, socklen_t *alen) {
    return wrap(_u_getsockname(s, asa, alen));
}

int u_shutdown(int s, int how) {
    return wrap(_u_shutdown(s, how));
}

ssize_t u_read(int fd, void *buf, size_t nbyte) {
    return wrap_ssize(_u_read(fd, buf, nbyte));
}

ssize_t u_write(int fd, const void *buf, size_t nbyte) {
    return wrap_ssize(_u_write(fd, buf, nbyte));
}

int u_ioctl(int fd, unsigned long com, void *data) {
    return wrap(_u_ioctl(fd, com, data));
}

int u_fcntl(int fd, int cmd, void *arg) {
    return wrap(_u_fcntl(fd, cmd, arg));
}

int u_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    return wrap(_u_poll(fds, nfds, timeout));
}

int u_kqueue(void) {
    return wrap(_u_kqueue());
}

int u_kevent(int fd, const struct kevent *changelist, int nchanges,
             struct kevent *eventlist, int nevents,
             const struct timespec *timeout) {
    return wrap(_u_kevent(fd, (const struct kevent *)changelist, nchanges, eventlist, nevents, timeout));
}

int u_set_nonblocking(int s, int nonblocking) {
    return wrap(_u_set_nonblocking(s, nonblocking));
}

int u_is_nonblocking(int s) {
    return _u_is_nonblocking(s);
}

int u_is_connecting(int s) {
    return _u_is_connecting(s);
}

int u_is_connected(int s) {
    return _u_is_connected(s);
}

int u_socket_error(int s) {
    return _u_socket_error(s);
}
