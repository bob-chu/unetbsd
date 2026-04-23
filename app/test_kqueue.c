#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <time.h>

/* Use our native Linux-like API */
#include "u_api.h"

#define SERVER_PORT 12345
#define SERVER_IP   "127.0.0.1"
#define MAX_EVENTS  10

/* NetBSD kevent macros (matching NetBSD event.h) */
#define EV_SET(kevp, id, filt, fl, ffl, d, ud)	\
do { \
	memset((kevp), 0, sizeof(struct kevent)); \
	(kevp)->ident = (uintptr_t)(id); \
	(kevp)->filter = (filt); \
	(kevp)->flags = (fl); \
	(kevp)->fflags = (ffl); \
	(kevp)->data = (d); \
	(kevp)->udata = (void *)(ud); \
} while(0)

#define EVFILT_READ     0U
#define EVFILT_WRITE    1U

#define EV_ADD          0x0001U
#define EV_DELETE       0x0002U
#define EV_ENABLE       0x0004U
#define EV_DISABLE      0x0008U

extern void netbsd_init(void);

int main(int argc, char *argv[])
{
    int ret;
    int server_fd, client_fd, kq;

    printf("[main] Starting test_kqueue...\n"); fflush(stdout);
    netbsd_init();
    printf("[main] netbsd_init() done.\n"); fflush(stdout);

    /* 1. Create Server Socket */
    server_fd = u_socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("u_socket (server) failed");
        exit(1);
    }
    printf("Server socket created: fd=%d\n", server_fd);

    u_set_nonblocking(server_fd, 1);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(SERVER_PORT);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = u_bind(server_fd, (struct sockaddr *)&sin, sizeof(sin));
    if (ret < 0) {
        perror("u_bind failed");
        exit(1);
    }

    ret = u_listen(server_fd, 5);
    if (ret < 0) {
        perror("u_listen failed");
        exit(1);
    }
    printf("Server listening on port %d\n", SERVER_PORT);

    /* 2. Create kqueue */
    kq = u_kqueue();
    if (kq < 0) {
        perror("u_kqueue failed");
        exit(1);
    }
    printf("kqueue created: fd=%d\n", kq);

    /* 3. Register server socket in kqueue */
    struct kevent kev;
    EV_SET(&kev, server_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    ret = u_kevent(kq, &kev, 1, NULL, 0, NULL);
    if (ret < 0) {
        perror("u_kevent (add server) failed");
        exit(1);
    }

    /* 4. Create Client Socket */
    client_fd = u_socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("u_socket (client) failed");
        exit(1);
    }
    printf("Client socket created: fd=%d\n", client_fd);

    u_set_nonblocking(client_fd, 1);

    /* Connect to SERVER_IP which we set in netbsd_init */
    struct sockaddr_in remote_sin;
    memset(&remote_sin, 0, sizeof(remote_sin));
    remote_sin.sin_family = AF_INET;
    remote_sin.sin_port = htons(SERVER_PORT);
    remote_sin.sin_addr.s_addr = inet_addr(SERVER_IP);

    ret = u_connect(client_fd, (struct sockaddr *)&remote_sin, sizeof(remote_sin));
    if (ret < 0 && errno != EINPROGRESS) {
        perror("u_connect failed");
        exit(1);
    }
    printf("Client connecting to %s:%d...\n", SERVER_IP, SERVER_PORT);

    struct kevent client_kevs[2];
    EV_SET(&client_kevs[0], client_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    EV_SET(&client_kevs[1], client_fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, NULL);
    u_kevent(kq, client_kevs, 2, NULL, 0, NULL);

    /* 5. Event Loop */
    printf("Entering event loop...\n");
    struct kevent events[MAX_EVENTS];
    int loop_count = 0;
    int client_connected = 0;
    int server_accepted_fd = -1;
    int data_received = 0;

    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 10 * 1000000; /* 10ms */

    while (loop_count < 1000) {
        loop_count++;
        
        /* Stack is driven automatically inside u_kevent, u_accept, u_poll */
        int n = u_kevent(kq, NULL, 0, events, MAX_EVENTS, &timeout);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("u_kevent wait failed");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = (int)events[i].ident;
            printf("Got event: fd=%d, filter=%d, flags=0x%x\n", fd, events[i].filter, events[i].flags);
            
            if (fd == server_fd) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int new_fd = u_accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
                if (new_fd >= 0) {
                    printf("[Server] Accepted fd=%d from %s:%d\n", 
                            new_fd, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    u_set_nonblocking(new_fd, 1);
                    struct kevent accept_kev;
                    EV_SET(&accept_kev, new_fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
                    u_kevent(kq, &accept_kev, 1, NULL, 0, NULL);
                    server_accepted_fd = new_fd;
                }
            } else if (fd == client_fd) {
                int err = u_socket_error(client_fd);
                int connected = u_is_connected(client_fd);
                printf("[Client] Event: filter=%d, flags=0x%x, err=%d, connected=%d\n", 
                        events[i].filter, events[i].flags, err, connected);

                if (events[i].filter == EVFILT_WRITE && !client_connected) {
                    if (err == 0 && connected) {
                        printf("[Client] Connected!\n");
                        client_connected = 1;
                        const char *msg = "Hello!";
                        u_write(client_fd, (void*)msg, strlen(msg));
                    }
                } else if (events[i].filter == EVFILT_READ) {
                    char buf[1024];
                    ssize_t bytes = u_read(client_fd, buf, sizeof(buf)-1);
                    if (bytes > 0) {
                        buf[bytes] = 0;
                        printf("[Client] Received: %s\n", buf);
                        data_received = 1;
                    }
                }
            } else if (fd == server_accepted_fd) {
                if (events[i].filter == EVFILT_READ) {
                    char buf[1024];
                    ssize_t bytes = u_read(fd, buf, sizeof(buf)-1);
                    if (bytes > 0) {
                        buf[bytes] = 0;
                        printf("[Server] Received: %s\n", buf);
                        u_write(fd, (void*)"ACK", 3);
                    }
                }
            }
        }
        if (data_received) break;
        usleep(1000);
    }

    printf("Cleaning up...\n");
    u_close(client_fd);
    u_close(server_fd);
    u_close(kq);
    return 0;
}
