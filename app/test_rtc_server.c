#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "init.h"
#include "u_socket.h"
#include <arpa/inet.h>

static volatile int running = 1;

void sig_handler(int signo) {
    running = 0;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *if_name = "veth0";
    const char *ip = "10.0.0.1";
    char *mac_str = "02:00:00:00:00:01";
    
    if (argc == 1) {
        if_name = NULL;
        ip = NULL;
        mac_str = NULL;
    } else {
        if (argc > 1) if_name = argv[1];
        if (argc > 2) ip = argv[2];
    }

    // Initialize RTC mode
    if (netbsd_init_rtc(if_name, ip, mac_str) < 0) {
        fprintf(stderr, "Failed to init RTC mode\n");
        return 1;
    }

    // Create listening socket (Standard API, intercepted by shim)
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(5201);

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(fd, 10) < 0) {
        perror("listen");
        return 1;
    }
    
    // Set non-blocking standard way
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    printf("RTC Server listening on port 5201...\n");

    int client_fds[16]; // Support multiple clients
    for (int i=0; i<16; i++) client_fds[i] = -1;
    
    char buf[64 * 1024];
    uint64_t total_bytes = 0;
    time_t last_report = time(NULL);

    while (running) {
    // Drive stack
        netbsd_rtc_loop();

        // Accept new connections (loop until empty)
        while (1) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int new_fd = accept(fd, (struct sockaddr *)&client_addr, &addr_len);
            if (new_fd < 0) {
                 if (errno != EAGAIN && errno != EWOULDBLOCK) {
                     // perror("accept");
                 }
                 break;
            }
            
            int f = fcntl(new_fd, F_GETFL, 0);
            fcntl(new_fd, F_SETFL, f | O_NONBLOCK);
            
            int added = 0;
            for (int i=0; i<16; i++) {
                if (client_fds[i] == -1) {
                    client_fds[i] = new_fd;
                    printf("Client connected! (FD=%d, Index=%d)\n", new_fd, i);
                    fflush(stdout); 
                    added = 1;
                    break;
                }
            }
            if (!added) {
                printf("Too many clients, closing FD=%d\n", new_fd);
                close(new_fd);
            }
        }

        // Read from all clients
        int active_clients = 0;
        for (int i=0; i<16; i++) {
            if (client_fds[i] != -1) {
                active_clients++;
                int n = read(client_fds[i], buf, sizeof(buf));
                if (n > 0) {
                    total_bytes += n;
                } else if (n == 0) {
                    printf("Client disconnected (FD=%d)\n", client_fds[i]);
                    close(client_fds[i]);
                    client_fds[i] = -1;
                } else {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                         // Error
                    }
                }
            }
        }

        // Periodically report
        time_t now = time(NULL);
        if (now > last_report) {
            if (active_clients > 0 && total_bytes > 0) {
                printf("RX Throughput: %.2f Gbps (Clients: %d)\n", 
                       (double)total_bytes * 8 / 1e9, active_clients);
                fflush(stdout);
                total_bytes = 0;
            }
            last_report = now;
        }
    }
    return 0;
}
