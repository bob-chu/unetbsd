#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
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
    const char *client_ip = "10.0.0.2";
    const char *server_ip = "10.0.0.1";
    char *mac_str = "02:00:00:00:00:02";
    
    // Support running without args (Config File Mode)
    // If argc == 1, we assume config file is used, pass NULL to init
    if (argc == 1) {
         if_name = NULL;
         client_ip = NULL;
         mac_str = NULL;
         // server_ip remains default 10.0.0.1 or we could read from env?
         // Let's assume 10.0.0.1 for now or check args more carefully.
         if (getenv("TARGET_IP")) server_ip = getenv("TARGET_IP");
    } else {
        if (argc > 1) if_name = argv[1];
        if (argc > 2) client_ip = argv[2];
        if (argc > 3) server_ip = argv[3];
    }

    // Initialize RTC mode
    fprintf(stderr, "Calling netbsd_init_rtc...\n");
    if (netbsd_init_rtc(if_name, client_ip, mac_str) < 0) {
        fprintf(stderr, "Failed to init RTC mode\n");
        return 1;
    }
    fprintf(stderr, "netbsd_init_rtc success. Calling socket()...\n");
    // Create 2 sockets to mimic iperf3 (Control + Data)
    int fds[2];
    int connected[2] = {0, 0};
    
    printf("Opening 2 sockets (Control + Data)...\n");
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(server_ip);
    sin.sin_port = htons(5201);

    for (int i=0; i<2; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (fds[i] < 0) { perror("socket"); return 1; }
        
        int flags = fcntl(fds[i], F_GETFL, 0);
        fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        
        printf("Connecting socket %d...\n", i);
        int ret = connect(fds[i], (struct sockaddr *)&sin, sizeof(sin));
        if (ret == 0) {
             printf("Socket %d connected immediately!\n", i);
             connected[i] = 1; // Mark as connected if immediate
        } else if (ret < 0) {
             if (errno == EINPROGRESS) {
                  printf("Socket %d connect in progress...\n", i);
             } else {
                  perror("connect");
                  return 1;
             }
        }
        usleep(100000); // Wait 100ms
    }
    
    // Wait for both to connect
    int all_connected = 0;
    while (running && !all_connected) {
        netbsd_rtc_loop();
        
        int c = 0;
        for (int i=0; i<2; i++) {
            if (connected[i]) { c++; continue; }
            
            char dummy = 0;
            int n = write(fds[i], &dummy, 1); 
            if (n > 0 || errno == EISCONN) {
                 connected[i] = 1;
                 printf("Socket %d connected!\n", i);
                 c++;
            }
        }
        if (c == 2) all_connected = 1;
        usleep(1000);
    }
    
    if (!all_connected) {
        printf("Timed out waiting for connections.\n");
        return 1;
    }

    char buf[64 * 1024];
    memset(buf, 'A', sizeof(buf));
    uint64_t total_bytes = 0;
    time_t last_report = time(NULL);
    
    int data_sock = fds[1]; // Use second socket for data (arbitrary choice)

    while (running) {
        netbsd_rtc_loop(); // Drive stack

        // Send on Data Socket
        for (int i=0; i<4; i++) {
             int n = write(data_sock, buf, sizeof(buf));
             if (n > 0) {
                 total_bytes += n;
             } else if (n < 0) {
                 if (errno != EAGAIN && errno != EWOULDBLOCK) break;
             }
        }
        
        time_t now = time(NULL);
        if (now > last_report) {
            printf("TX Throughput: %.2f Gbps\n", (double)total_bytes * 8 / 1e9);
            fflush(stdout); 
            total_bytes = 0;
            last_report = now;
        }
    }
    close(fds[0]);
    close(fds[1]);
    return 0;
}
