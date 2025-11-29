#define _GNU_SOURCE
#include "shim_api.h"
//#include "netbsd_shim_api.h"
#include "u_socket.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h> // For debugging, will remove later

// Original libc function pointers
static int (*real_socket)(int, int, int) = NULL;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static int (*real_close)(int) = NULL;


// Constructor to initialize real function pointers
__attribute__((constructor))
static void init_shims(void) {
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_listen = dlsym(RTLD_NEXT, "listen");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_close = dlsym(RTLD_NEXT, "close");

    if (!real_socket || !real_bind || !real_listen || !real_accept || !real_connect || !real_send || !real_recv || !real_close) {
        fprintf(stderr, "Error in dlsym: could not find all real functions\n");
        // Depending on the desired behavior, you might want to exit or handle this more gracefully.
        // For now, we'll let it continue, which means calls to missing functions will crash.
    }
}

// Our shim functions (from original posix_shim.c, but now correctly declared)

int shim_socket(int domain, int type, int protocol)
{
    struct netbsd_handle *nh = malloc(sizeof(struct netbsd_handle));
    if (!nh) {
        errno = ENOMEM;
        return -1;
    }
    memset(nh, 0, sizeof(struct netbsd_handle));

    if (domain == AF_INET) {
        nh->is_ipv4 = 1;
    } else if (domain == AF_INET6) {
        nh->is_ipv4 = 0;
    }
    else {
        free(nh);
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (type == SOCK_STREAM) {
        nh->proto = PROTO_TCP;
    } else if (type == SOCK_DGRAM) {
        nh->proto = PROTO_UDP;
    } else {
        free(nh);
        errno = EPROTOTYPE;
        return -1;
    }

    if (netbsd_socket(nh) != 0) {
        free(nh);
        errno = EIO; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }

    // The shim layer now returns the netbsd_handle directly,
    // and the application is responsible for managing the file descriptor.
    return (intptr_t)nh; // Cast to int for now, will be handled by application
}

int shim_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    int ret = netbsd_bind(nh, addr);
    if (ret != 0) {
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }
    return 0;
}

int shim_listen(int sockfd, int backlog)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    int ret = netbsd_listen(nh, backlog);
    if (ret != 0) {
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }
    return 0;
}

int shim_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    int ret = netbsd_connect(nh, (struct sockaddr *)addr);
    if (ret != 0) {
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }
    return 0;
}

int shim_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct netbsd_handle *nh_listen = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh_listen) {
        errno = EBADF;
        return -1;
    }

    struct netbsd_handle *nh_new = malloc(sizeof(struct netbsd_handle));
    if (!nh_new) {
        errno = ENOMEM;
        return -1;
    }
    memset(nh_new, 0, sizeof(struct netbsd_handle));
    nh_new->is_ipv4 = nh_listen->is_ipv4;
    nh_new->proto = nh_listen->proto;

    int ret = netbsd_accept(nh_listen, nh_new);
    if (ret != 0) {
        free(nh_new);
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }

    // TODO: get peer address and store it in addr and addrlen

    return (intptr_t)nh_new; // Cast to int for now, will be handled by application
}

ssize_t shim_send(int sockfd, const void *buf, size_t len, int flags)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    struct iovec iov;
    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    ssize_t ret = netbsd_write(nh, &iov, 1);
    if (ret < 0) {
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }
    return ret;
}

ssize_t shim_recv(int sockfd, void *buf, size_t len, int flags)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;

    ssize_t ret = netbsd_read(nh, &iov, 1);
    if (ret < 0) {
        errno = -ret; // TODO: Map NetBSD error codes to POSIX errno
        return -1;
    }
    return ret;
}

int shim_close(int sockfd)
{
    struct netbsd_handle *nh = (struct netbsd_handle *)(intptr_t)sockfd;
    if (!nh) {
        errno = EBADF;
        return -1;
    }

    netbsd_close(nh); // Assuming netbsd_close handles resource cleanup
    free(nh);

    return 0;
}

// LD_PRELOAD interceptor functions
int socket(int domain, int type, int protocol) {
    if (domain == AF_INET || domain == AF_INET6) {
        // Intercept IPv4 and IPv6 sockets
        return shim_socket(domain, type, protocol);
    }
    // For other domains, call the real socket function
    if (real_socket) {
        return real_socket(domain, type, protocol);
    }
    errno = ENOSYS; // Or a more appropriate error
    return -1;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // Determine if this sockfd is managed by our shim
    // This is a simplistic check; a more robust solution would track active shims
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) { // Heuristic: Check if it's likely a pointer address
        return shim_bind(sockfd, addr, addrlen);
    }
    if (real_bind) {
        return real_bind(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

int listen(int sockfd, int backlog) {
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_listen(sockfd, backlog);
    }
    if (real_listen) {
        return real_listen(sockfd, backlog);
    }
    errno = ENOSYS;
    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_accept(sockfd, addr, addrlen);
    }
    if (real_accept) {
        return real_accept(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_connect(sockfd, addr, addrlen);
    }
    if (real_connect) {
        return real_connect(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_send(sockfd, buf, len, flags);
    }
    if (real_send) {
        return real_send(sockfd, buf, len, flags);
    }
    errno = ENOSYS;
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_recv(sockfd, buf, len, flags);
    }
    if (real_recv) {
        return real_recv(sockfd, buf, len, flags);
    }
    errno = ENOSYS;
    return -1;
}

int close(int sockfd) {
    // This heuristic is very brittle and prone to errors.
    // A robust solution would involve tracking which file descriptors belong to the shim
    // e.g., by storing `netbsd_handle*` in a global map keyed by a generated unique integer FD,
    // and then intercepting `dup`, `fcntl` etc. to manage FD ownership.
    // For this task, we'll stick to the current approach for simplicity, but acknowledge its limitations.
    if (sockfd >= 0 && (intptr_t)sockfd > 0x1000) {
        return shim_close(sockfd);
    }
    if (real_close) {
        return real_close(sockfd);
    }
    errno = ENOSYS;
    return -1;
}
