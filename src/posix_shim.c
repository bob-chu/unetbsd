#define _GNU_SOURCE
#include "shim_api.h"
//#include "netbsd_shim_api.h"
#include "u_socket.h"
#include "../include/u_cmdqueue.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <poll.h>

// Command queue for communication between app and NetBSD stack
static cmd_queue_t app_to_stack_queue;
static int g_shutdown = 0;
static int g_eventfd = -1;
static pthread_t g_netbsd_thread;
static void netbsd_stack_init(void);

// Original libc function pointers
static int (*real_socket)(int, int, int) = NULL;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static int (*real_close)(int) = NULL;


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
        exit(1);
    }
    
    // Initialize command queue
    cmd_queue_init(&app_to_stack_queue);
    
    // Create eventfd for thread notification
    g_eventfd = eventfd(0, EFD_NONBLOCK);
    if (g_eventfd < 0) {
        perror("eventfd");
        exit(1);
    }
    
    // Initialize NetBSD protocol stack
    netbsd_init();
    netbsd_stack_init();
    
    fprintf(stderr, "[Shim] Initialized successfully\n");
}

__attribute__((destructor))
static void cleanup_shims(void) {
    // Send shutdown command
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_SHUTDOWN;
    sem_init(&cmd.completion, 0, 0);
    
    cmd_queue_enqueue(&app_to_stack_queue, &cmd);
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    // Wait for thread to exit
    pthread_join(g_netbsd_thread, NULL);
    
    close(g_eventfd);
    fprintf(stderr, "[Shim] Cleaned up\n");
}

// Our shim functions (from original posix_shim.c, but now correctly declared)

int shim_socket(int domain, int type, int protocol)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_SOCKET;
    cmd.data = malloc(sizeof(int) * 3);
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    ((int*)cmd.data)[0] = domain;
    ((int*)cmd.data)[1] = type;
    ((int*)cmd.data)[2] = protocol;
    cmd.data_len = sizeof(int) * 3;
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int fd = cmd.result;
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return fd;
}

int shim_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_BIND;
    cmd.fd = sockfd;
    cmd.data = malloc(addrlen);
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(cmd.data, addr, addrlen);
    cmd.data_len = addrlen;
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int ret = cmd.result;
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

int shim_listen(int sockfd, int backlog)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_LISTEN;
    cmd.fd = sockfd;
    cmd.data = malloc(sizeof(int));
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    *(int*)cmd.data = backlog;
    cmd.data_len = sizeof(int);
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int ret = cmd.result;
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

int shim_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_CONNECT;
    cmd.fd = sockfd;
    cmd.data = malloc(addrlen);
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(cmd.data, addr, addrlen);
    cmd.data_len = addrlen;
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int ret = cmd.result;
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

int shim_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_ACCEPT;
    cmd.fd = sockfd;
    cmd.data = NULL;
    cmd.data_len = 0;
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int new_fd = cmd.result;
    // TODO: Handle addr and addrlen retrieval if needed
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return new_fd;
}

ssize_t shim_send(int sockfd, const void *buf, size_t len, int flags)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_SEND;
    cmd.fd = sockfd;
    cmd.data = malloc(len + sizeof(int));
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    *(int*)cmd.data = flags;
    memcpy((char*)cmd.data + sizeof(int), buf, len);
    cmd.data_len = len + sizeof(int);
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    ssize_t ret = cmd.result;
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

ssize_t shim_recv(int sockfd, void *buf, size_t len, int flags)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_RECV;
    cmd.fd = sockfd;
    cmd.data = malloc(sizeof(size_t) + sizeof(int));
    if (!cmd.data) {
        errno = ENOMEM;
        return -1;
    }
    *(size_t*)cmd.data = len;
    *((int*)((char*)cmd.data + sizeof(size_t))) = flags;
    cmd.data_len = sizeof(size_t) + sizeof(int);
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        free(cmd.data);
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    ssize_t ret = cmd.result;
    if (ret > 0 && cmd.data) {
        memcpy(buf, cmd.data, ret);
    }
    free(cmd.data);
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

int shim_close(int sockfd)
{
    cmd_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.type = CMD_CLOSE;
    cmd.fd = sockfd;
    cmd.data = NULL;
    cmd.data_len = 0;
    
    sem_init(&cmd.completion, 0, 0);
    if (cmd_queue_enqueue(&app_to_stack_queue, &cmd) != 0) {
        errno = EAGAIN;
        return -1;
    }
    
    // Notify NetBSD thread
    uint64_t val = 1;
    write(g_eventfd, &val, sizeof(val));
    
    // Wait for NetBSD thread to process the command
    sem_wait(&cmd.completion);
    sem_destroy(&cmd.completion);
    
    int ret = cmd.result;
    if (cmd.error_code != 0) {
        errno = cmd.error_code;
        return -1;
    }
    return ret;
}

static void execute_socket_cmd(cmd_t *cmd) {
    int *data = (int *)cmd->data;
    int domain = data[0];
    int type = data[1];
    int protocol = data[2];
    
    struct netbsd_handle *nh = malloc(sizeof(struct netbsd_handle));
    if (!nh) {
        cmd->error_code = ENOMEM;
        cmd->result = -1;
        return;
    }
    memset(nh, 0, sizeof(struct netbsd_handle));

    if (domain == AF_INET) {
        nh->is_ipv4 = 1;
    } else if (domain == AF_INET6) {
        nh->is_ipv4 = 0;
    } else {
        free(nh);
        cmd->error_code = EAFNOSUPPORT;
        cmd->result = -1;
        return;
    }

    if (type == SOCK_STREAM) {
        nh->proto = PROTO_TCP;
    } else if (type == SOCK_DGRAM) {
        nh->proto = PROTO_UDP;
    } else {
        free(nh);
        cmd->error_code = EPROTOTYPE;
        cmd->result = -1;
        return;
    }

    if (netbsd_socket(nh) != 0) {
        free(nh);
        cmd->error_code = EIO; // TODO: Map NetBSD error codes to POSIX errno
        cmd->result = -1;
        return;
    }

    nh->fd = u_fd_alloc(nh);
    if (nh->fd < 0) {
        netbsd_close(nh);
        free(nh);
        cmd->error_code = EMFILE;
        cmd->result = -1;
        return;
    }
    
    cmd->result = nh->fd;
    cmd->error_code = 0;
}

static void execute_bind_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    int ret = netbsd_bind(nh, (const struct sockaddr *)cmd->data);
    cmd->result = ret;
    cmd->error_code = (ret != 0) ? -ret : 0;
}

static void execute_listen_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    int backlog = *(int*)cmd->data;
    int ret = netbsd_listen(nh, backlog);
    cmd->result = ret;
    cmd->error_code = (ret != 0) ? -ret : 0;
}

static void execute_connect_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    int ret = netbsd_connect(nh, (struct sockaddr *)cmd->data);
    cmd->result = ret;
    cmd->error_code = (ret != 0) ? -ret : 0;
}

static void execute_accept_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh_listen = fd_get(cmd->fd);
    if (!nh_listen) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    struct netbsd_handle *nh_new = malloc(sizeof(struct netbsd_handle));
    if (!nh_new) {
        cmd->error_code = ENOMEM;
        cmd->result = -1;
        return;
    }
    memset(nh_new, 0, sizeof(struct netbsd_handle));
    nh_new->is_ipv4 = nh_listen->is_ipv4;
    nh_new->proto = nh_listen->proto;

    int ret = netbsd_accept(nh_listen, nh_new);
    if (ret != 0) {
        free(nh_new);
        cmd->error_code = -ret; // TODO: Map NetBSD error codes to POSIX errno
        cmd->result = -1;
        return;
    }

    nh_new->fd = u_fd_alloc(nh_new);
    if (nh_new->fd < 0) {
        netbsd_close(nh_new);
        free(nh_new);
        cmd->error_code = EMFILE;
        cmd->result = -1;
        return;
    }
    
    cmd->result = nh_new->fd;
    cmd->error_code = 0;
}

static void execute_send_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    int flags = *(int*)cmd->data;
    struct iovec iov;
    iov.iov_base = (void *)(cmd->data + sizeof(int));
    iov.iov_len = cmd->data_len - sizeof(int);

    ssize_t ret = netbsd_write(nh, &iov, 1);
    cmd->result = ret;
    cmd->error_code = (ret < 0) ? -ret : 0;
}

static void execute_recv_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    size_t len = *(size_t*)cmd->data;
    //int flags = *(int*)(cmd->data + sizeof(size_t));
    
    void *buf = malloc(len);
    if (!buf) {
        cmd->error_code = ENOMEM;
        cmd->result = -1;
        return;
    }
    
    struct iovec iov;
    iov.iov_base = buf;
    iov.iov_len = len;

    ssize_t ret = netbsd_read(nh, &iov, 1);
    if (ret >= 0) {
        cmd->data = buf;
    } else {
        free(buf);
    }
    cmd->result = ret;
    cmd->error_code = (ret < 0) ? -ret : 0;
}

static void execute_close_cmd(cmd_t *cmd) {
    struct netbsd_handle *nh = fd_get(cmd->fd);
    if (!nh) {
        cmd->error_code = EBADF;
        cmd->result = -1;
        return;
    }

    netbsd_close(nh);
    u_fd_free(cmd->fd);
    free(nh);
    cmd->result = 0;
    cmd->error_code = 0;
}

static void *netbsd_stack_thread(void *arg) {
    fprintf(stderr, "[NetBSD Thread] Started\n");
    
    struct pollfd pfd;
    pfd.fd = g_eventfd;
    pfd.events = POLLIN;
    
    while (!g_shutdown) {
        // 1. Process command queue
        cmd_t *cmd;
        while ((cmd = cmd_queue_dequeue(&app_to_stack_queue)) != NULL) {
            switch (cmd->type) {
                case CMD_SOCKET:
                    execute_socket_cmd(cmd);
                    break;
                case CMD_BIND:
                    execute_bind_cmd(cmd);
                    break;
                case CMD_LISTEN:
                    execute_listen_cmd(cmd);
                    break;
                case CMD_CONNECT:
                    execute_connect_cmd(cmd);
                    break;
                case CMD_ACCEPT:
                    execute_accept_cmd(cmd);
                    break;
                case CMD_SEND:
                    execute_send_cmd(cmd);
                    break;
                case CMD_RECV:
                    execute_recv_cmd(cmd);
                    break;
                case CMD_CLOSE:
                    execute_close_cmd(cmd);
                    break;
                case CMD_SHUTDOWN:
                    g_shutdown = 1;
                    break;
                default:
                    cmd->error_code = EINVAL;
                    cmd->result = -1;
            }
            
            // Notify calling thread of completion
            sem_post(&cmd->completion);
        }
        
        // 2. Drive NetBSD protocol stack (handle timers, packet processing, etc.)
        // netbsd_stack_poll();  // Placeholder, to be implemented
        
        // 3. Handle DPDK packet reception
        // dpdk_rx_poll();  // Placeholder, to be implemented
        
        // 4. Brief sleep or wait for events
        int ret = poll(&pfd, 1, 1);  // 1ms timeout
        if (ret > 0) {
            uint64_t val;
            read(g_eventfd, &val, sizeof(val));
        }
    }
    
    fprintf(stderr, "[NetBSD Thread] Stopped\n");
    return NULL;
}

#include <rte_eal.h>

static void netbsd_stack_init(void) {
    // Start NetBSD protocol stack thread
    if (pthread_create(&g_netbsd_thread, NULL, netbsd_stack_thread, NULL) != 0) {
        perror("pthread_create");
        exit(1);
    }
    // Call DPDK initialization to ensure linking and initialization
    int argc = 0;
    char *argv[] = { NULL };
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Error initializing DPDK EAL: %d\n", ret);
        // Don't exit, just log the error
    } else {
        fprintf(stderr, "[Shim] DPDK EAL initialized successfully\n");
    }
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
    // Check if this sockfd is managed by our shim using fd_get
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_bind(sockfd, addr, addrlen);
    }
    if (real_bind) {
        return real_bind(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

int listen(int sockfd, int backlog) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_listen(sockfd, backlog);
    }
    if (real_listen) {
        return real_listen(sockfd, backlog);
    }
    errno = ENOSYS;
    return -1;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_accept(sockfd, addr, addrlen);
    }
    if (real_accept) {
        return real_accept(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_connect(sockfd, addr, addrlen);
    }
    if (real_connect) {
        return real_connect(sockfd, addr, addrlen);
    }
    errno = ENOSYS;
    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_send(sockfd, buf, len, flags);
    }
    if (real_send) {
        return real_send(sockfd, buf, len, flags);
    }
    errno = ENOSYS;
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_recv(sockfd, buf, len, flags);
    }
    if (real_recv) {
        return real_recv(sockfd, buf, len, flags);
    }
    errno = ENOSYS;
    return -1;
}

int close(int sockfd) {
    struct netbsd_handle *nh = fd_get(sockfd);
    if (nh) {
        return shim_close(sockfd);
    }
    if (real_close) {
        return real_close(sockfd);
    }
    errno = ENOSYS;
    return -1;
}
