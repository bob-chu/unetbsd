#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <ev.h>
#include <getopt.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#define DEFAULT_MAX_CLIENTS 10

typedef struct {
    struct ev_loop *loop;
    char *ptcp_socket_path;
    char *ptm_socket_path;
    int ptcp_fd;
    int listen_fd;
    int *client_fds;
    ev_io *client_watchers;
    int num_clients;
    int max_clients;
    ev_io ptcp_watcher;
    ev_io listen_watcher;
} ptm_t;

static ptm_t g_ptm;

// Forward declarations
static void ptcp_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void listen_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void client_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void remove_client(int idx);

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --ptcp-socket <path> --ptm-socket <path> [--max-clients-clients <num>] [--max-clients-servers <num>]\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    char *ptcp_socket_path = NULL;
    char *ptm_socket_path = NULL;
    int max_clients_clients = DEFAULT_MAX_CLIENTS;
    int max_clients_servers = DEFAULT_MAX_CLIENTS;

    static struct option long_options[] = {
        {"ptcp-socket", required_argument, 0, 'p'},
        {"ptm-socket", required_argument, 0, 't'},
        {"max-clients-clients", required_argument, 0, 'c'},
        {"max-clients-servers", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:c:s:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                ptcp_socket_path = strdup(optarg);
                break;
            case 't':
                ptm_socket_path = strdup(optarg);
                break;
            case 'c':
                max_clients_clients = atoi(optarg);
                break;
            case 's':
                max_clients_servers = atoi(optarg);
                break;
            default:
                usage(argv[0]);
        }
    }

    if (!ptcp_socket_path || !ptm_socket_path || max_clients_clients <= 0 || max_clients_servers <= 0) {
        usage(argv[0]);
    }

    g_ptm.loop = EV_DEFAULT;
    g_ptm.ptcp_socket_path = ptcp_socket_path;
    g_ptm.ptm_socket_path = ptm_socket_path;
    g_ptm.ptcp_fd = -1;
    g_ptm.listen_fd = -1;
    g_ptm.num_clients = 0;
    g_ptm.max_clients = max_clients_clients + max_clients_servers;

    // Allocate client arrays
    g_ptm.client_fds = (int*)malloc(g_ptm.max_clients * sizeof(int));
    g_ptm.client_watchers = (ev_io*)malloc(g_ptm.max_clients * sizeof(ev_io));
    if (!g_ptm.client_fds || !g_ptm.client_watchers) {
        perror("Failed to allocate client arrays");
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    // Create shared memory for http_client stats using mmap on temp file
    char client_shm_path[256];
    snprintf(client_shm_path, sizeof(client_shm_path), "/tmp/ptm_client_stats_%d", getpid());
    int fd_client = open(client_shm_path, O_CREAT | O_RDWR, 0666);
    if (fd_client == -1) {
        perror("Failed to create temp file for client stats");
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    size_t client_stats_size = sizeof(stats_t) * max_clients_clients;
    if (ftruncate(fd_client, client_stats_size) == -1) {
        perror("Failed to set size for client stats temp file");
        close(fd_client);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    void *shm_client_stats = mmap(NULL, client_stats_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_client, 0);
    if (shm_client_stats == MAP_FAILED) {
        perror("Failed to mmap client stats");
        close(fd_client);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    memset(shm_client_stats, 0, client_stats_size);
    close(fd_client); // Can close fd after mmap

    // Create shared memory for http_server stats using mmap on temp file
    char server_shm_path[256];
    snprintf(server_shm_path, sizeof(server_shm_path), "/tmp/ptm_server_stats_%d", getpid());
    int fd_server = open(server_shm_path, O_CREAT | O_RDWR, 0666);
    if (fd_server == -1) {
        perror("Failed to create temp file for server stats");
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    size_t server_stats_size = sizeof(stats_t) * max_clients_servers;
    if (ftruncate(fd_server, server_stats_size) == -1) {
        perror("Failed to set size for server stats temp file");
        close(fd_server);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    void *shm_server_stats = mmap(NULL, server_stats_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_server, 0);
    if (shm_server_stats == MAP_FAILED) {
        perror("Failed to mmap server stats");
        close(fd_server);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }
    memset(shm_server_stats, 0, server_stats_size);
    close(fd_server); // Can close fd after mmap

    // Connect to ptcp socket
    g_ptm.ptcp_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_ptm.ptcp_fd == -1) {
        perror("Failed to create socket for ptcp");
        munmap(shm_server_stats, server_stats_size);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    struct sockaddr_un ptcp_addr;
    memset(&ptcp_addr, 0, sizeof(ptcp_addr));
    ptcp_addr.sun_family = AF_UNIX;
    strncpy(ptcp_addr.sun_path, g_ptm.ptcp_socket_path, sizeof(ptcp_addr.sun_path) - 1);

    if (connect(g_ptm.ptcp_fd, (struct sockaddr*)&ptcp_addr, sizeof(ptcp_addr)) == -1) {
        perror("Failed to connect to ptcp socket");
        close(g_ptm.ptcp_fd);
        munmap(shm_server_stats, server_stats_size);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    printf("Connected to ptcp socket: %s\n", g_ptm.ptcp_socket_path);

    // Start listening on ptm socket
    g_ptm.listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_ptm.listen_fd == -1) {
        perror("Failed to create listen socket");
        close(g_ptm.ptcp_fd);
        munmap(shm_server_stats, server_stats_size);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    struct sockaddr_un listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    strncpy(listen_addr.sun_path, g_ptm.ptm_socket_path, sizeof(listen_addr.sun_path) - 1);

    unlink(g_ptm.ptm_socket_path); // Remove if exists
    if (bind(g_ptm.listen_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) == -1) {
        perror("Failed to bind listen socket");
        close(g_ptm.ptcp_fd);
        close(g_ptm.listen_fd);
        munmap(shm_server_stats, server_stats_size);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    if (listen(g_ptm.listen_fd, 5) == -1) {
        perror("Failed to listen on socket");
        close(g_ptm.ptcp_fd);
        close(g_ptm.listen_fd);
        munmap(shm_server_stats, server_stats_size);
        unlink(server_shm_path);
        munmap(shm_client_stats, client_stats_size);
        unlink(client_shm_path);
        free(g_ptm.client_fds);
        free(g_ptm.client_watchers);
        free(g_ptm.ptcp_socket_path);
        free(g_ptm.ptm_socket_path);
        return 1;
    }

    printf("Listening on ptm socket: %s\n", g_ptm.ptm_socket_path);

    // Set up watchers
    ev_io_init(&g_ptm.ptcp_watcher, ptcp_io_cb, g_ptm.ptcp_fd, EV_READ);
    ev_io_start(g_ptm.loop, &g_ptm.ptcp_watcher);

    ev_io_init(&g_ptm.listen_watcher, listen_io_cb, g_ptm.listen_fd, EV_READ);
    ev_io_start(g_ptm.loop, &g_ptm.listen_watcher);

    // Run event loop
    ev_run(g_ptm.loop, 0);

    // Cleanup
    close(g_ptm.ptcp_fd);
    close(g_ptm.listen_fd);
    unlink(g_ptm.ptm_socket_path);
    munmap(shm_server_stats, server_stats_size);
    unlink(server_shm_path);
    munmap(shm_client_stats, client_stats_size);
    unlink(client_shm_path);
    free(g_ptm.client_fds);
    free(g_ptm.client_watchers);
    free(g_ptm.ptcp_socket_path);
    free(g_ptm.ptm_socket_path);

    return 0;
}

static void ptcp_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    if (revents & EV_READ) {
        char buffer[4096];
        ssize_t n = recv(g_ptm.ptcp_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Received from ptcp: %s\n", buffer);

            // Forward to all connected clients
            for (int i = 0; i < g_ptm.num_clients; i++) {
                if (send(g_ptm.client_fds[i], buffer, n, 0) == -1) {
                    perror("Failed to send to client");
                    remove_client(i);
                    i--; // Adjust index after removal
                }
            }
        } else if (n == 0) {
            printf("Ptcp connection closed\n");
            ev_io_stop(loop, w);
            close(g_ptm.ptcp_fd);
            g_ptm.ptcp_fd = -1;
        } else {
            perror("Error reading from ptcp");
            ev_io_stop(loop, w);
            close(g_ptm.ptcp_fd);
            g_ptm.ptcp_fd = -1;
        }
    }
}

static void listen_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    if (revents & EV_READ) {
        int client_fd = accept(g_ptm.listen_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("Failed to accept client");
            return;
        }

        if (g_ptm.num_clients >= g_ptm.max_clients) {
            printf("Max clients reached, rejecting\n");
            close(client_fd);
            return;
        }

        printf("Accepted client connection\n");
        g_ptm.client_fds[g_ptm.num_clients] = client_fd;
        ev_io_init(&g_ptm.client_watchers[g_ptm.num_clients], client_io_cb, client_fd, EV_READ);
        g_ptm.client_watchers[g_ptm.num_clients].data = (void*)(uintptr_t)g_ptm.num_clients;
        ev_io_start(loop, &g_ptm.client_watchers[g_ptm.num_clients]);
        g_ptm.num_clients++;
    }
}

static void client_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int idx = (int)(uintptr_t)w->data;

    if (revents & EV_READ) {
        char buffer[4096];
        ssize_t n = recv(g_ptm.client_fds[idx], buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Received from client %d: %s\n", idx, buffer);

            // Forward to ptcp
            if (g_ptm.ptcp_fd != -1) {
                if (send(g_ptm.ptcp_fd, buffer, n, 0) == -1) {
                    perror("Failed to send to ptcp");
                }
            }
        } else if (n == 0) {
            printf("Client %d connection closed\n", idx);
            remove_client(idx);
        } else {
            perror("Error reading from client");
            remove_client(idx);
        }
    }
}

static void remove_client(int idx) {
    ev_io_stop(g_ptm.loop, &g_ptm.client_watchers[idx]);
    close(g_ptm.client_fds[idx]);

    // Shift remaining clients
    for (int i = idx; i < g_ptm.num_clients - 1; i++) {
        g_ptm.client_fds[i] = g_ptm.client_fds[i + 1];
        g_ptm.client_watchers[i] = g_ptm.client_watchers[i + 1];
        g_ptm.client_watchers[i].data = (void*)(uintptr_t)i;
    }
    g_ptm.num_clients--;
}
