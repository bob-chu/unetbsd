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
#include "../perf_tool/metrics.h"
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h> // For fstat
#include "../perf_tool/deps/cjson/cJSON.h" // For JSON processing
#include <sys/stat.h>
#include "common.h"

#define DEFAULT_MAX_CLIENTS 10

typedef enum {
    CLIENT_TYPE_UNKNOWN = 0,
    CLIENT_TYPE_HTTP_CLIENT,
    CLIENT_TYPE_HTTP_SERVER,
    CLIENT_TYPE_PIPE_CLIENT // Add pipe client type
} CLIENT_TYPE;

typedef struct {
    int idx;
    CLIENT_TYPE type;
    // Add shared memory related info
    void *shm_base;
    size_t shm_size;
    int check_status_flag; // Added to track readiness for 'check' command
} client_info_t;

typedef struct {
    struct ev_loop *loop;
    char *ptcp_socket_path;
    char *ptm_socket_path;
    int ptcp_fd;
    int listen_fd;
    int *client_fds;
    ev_io *client_watchers;
    client_info_t **client_info_array; // Array of pointers to client_info_t
    int num_clients;
    int max_clients;
    ev_io ptcp_watcher;
    ev_io listen_watcher;
    ev_timer stats_timer;
    int test_running;
} ptm_t;

static ptm_t g_ptm;
static void *g_shm_client_stats = NULL;
static void *g_shm_server_stats = NULL;
static int g_max_clients_clients = 0;
static int g_max_clients_servers = 0;
static size_t g_client_stats_size = 0;
static size_t g_server_stats_size = 0;
static char g_client_shm_path[256];
static char g_server_shm_path[256];

// Forward declarations
static void ptcp_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void listen_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void client_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void remove_client(int idx);
static void send_aggregated_stats_response(int fd); // New forward declaration
static void forward_to_clients(const char *message, size_t len); // New forward declaration

static void stats_timer_cb(struct ev_loop *loop, ev_timer *w, int revents) {
    if (g_ptm.test_running && g_ptm.ptcp_fd != -1) {
        send_aggregated_stats_response(g_ptm.ptcp_fd);
    }
}

// Helper to convert stats_t to cJSON
static cJSON* stats_to_cjson(const stats_t *stats) {
    cJSON *json = cJSON_CreateObject();
    if (!json) return NULL;

#define X(name) cJSON_AddNumberToObject(json, #name, stats->name);
    STATS_FIELDS
    STATS_HTTP_FIELDS
    STATS_TCP_FIELDS
    STATS_UDP_FIELDS
    STATS_PHASE_FIELD
#undef X
    return json;
}
#if 0
static CLIENT_TYPE get_client_type_from_string(const char *type_str) {
    if (strcmp(type_str, "HTTP_CLIENT") == 0) {
        return CLIENT_TYPE_HTTP_CLIENT;
    } else if (strcmp(type_str, "HTTP_SERVER") == 0) {
        return CLIENT_TYPE_HTTP_SERVER;
    } else if (strcmp(type_str, "PIPE_CLIENT") == 0) {
        return CLIENT_TYPE_PIPE_CLIENT;
    }
    return CLIENT_TYPE_UNKNOWN;
}
#endif
static void aggregate_stats(stats_t *out_stats, int client_role_filter) {
    memset(out_stats, 0, sizeof(stats_t));

    if (client_role_filter == 0) { // Aggregate client stats
        for (int i = 0; i < g_max_clients_clients; i++) {
            stats_t *client_stat = (stats_t *)((char *)g_shm_client_stats + (i * sizeof(stats_t)));
#define X(name) out_stats->name += client_stat->name;
            STATS_FIELDS
            STATS_HTTP_FIELDS
            STATS_TCP_FIELDS
            STATS_UDP_FIELDS
#undef X
            if (i == 0) { // Only set these once from the first client
                out_stats->client_role = 1;
                out_stats->time_index = client_stat->time_index;
                out_stats->current_phase = client_stat->current_phase;
            }
        }
    } else if (client_role_filter == 1) { // Aggregate server stats
        for (int i = 0; i < g_max_clients_servers; i++) {
            stats_t *server_stat = (stats_t *)((char *)g_shm_server_stats + (i * sizeof(stats_t)));
#define X(name) out_stats->name += server_stat->name;
            STATS_FIELDS
            STATS_HTTP_FIELDS
            STATS_TCP_FIELDS
            STATS_UDP_FIELDS
#undef X
            if (i == 0) { // Only set these once from the first server
                out_stats->server_role = 1;
                out_stats->time_index = server_stat->time_index;
                out_stats->current_phase = server_stat->current_phase;
            }
        }
    }
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --ptcp-socket <path> --ptm-socket <path> [--max-clients-clients <num>] [--max-clients-servers <num>]\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    char *ptcp_socket_path = NULL;
    char *ptm_socket_path = NULL;
    int max_clients_clients = DEFAULT_MAX_CLIENTS;
    int max_clients_servers = DEFAULT_MAX_CLIENTS;
    int fd_client = -1;
    void *shm_client_stats_local = MAP_FAILED;
    int fd_server = -1;
    void *shm_server_stats_local = MAP_FAILED;
    int *client_fds_local = NULL;
    ev_io *client_watchers_local = NULL;
    client_info_t **client_info_array_local = NULL;
    int ptcp_fd_local = -1;
    int listen_fd_local = -1;
    int ret = 1; // Assume failure by default
    int ptm_socket_bound = 0; // Flag to indicate if ptm_socket_path has been bound

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
                if (!ptcp_socket_path) {
                    perror("Failed to duplicate ptcp_socket_path");
                    goto cleanup;
                }
                break;
            case 't':
                ptm_socket_path = strdup(optarg);
                if (!ptm_socket_path) {
                    perror("Failed to duplicate ptm_socket_path");
                    goto cleanup;
                }
                break;
            case 'c':
                max_clients_clients = atoi(optarg);
                break;
            case 's':
                max_clients_servers = atoi(optarg);
                break;
            default:
                usage(argv[0]);
                goto cleanup; // usage prints and exits, but this is for consistency
        }
    }

    if (!ptcp_socket_path || !ptm_socket_path || max_clients_clients <= 0 || max_clients_servers <= 0) {
        usage(argv[0]);
        goto cleanup;
    }

    g_max_clients_clients = max_clients_clients;
    g_max_clients_servers = max_clients_servers;
    g_client_stats_size = sizeof(stats_t) * max_clients_clients;
    g_server_stats_size = sizeof(stats_t) * max_clients_servers;

    g_ptm.loop = EV_DEFAULT;
    g_ptm.ptcp_socket_path = ptcp_socket_path;
    g_ptm.ptm_socket_path = ptm_socket_path;
    g_ptm.ptcp_fd = ptcp_fd_local;
    g_ptm.listen_fd = listen_fd_local;
    g_ptm.num_clients = 0;
    g_ptm.max_clients = max_clients_clients + max_clients_servers;
    g_ptm.test_running = 0;

    // Allocate client arrays
    client_fds_local = (int*)malloc(g_ptm.max_clients * sizeof(int));
    if (!client_fds_local) {
        perror("Failed to allocate client_fds_local");
        goto cleanup;
    }
    client_watchers_local = (ev_io*)malloc(g_ptm.max_clients * sizeof(ev_io));
    if (!client_watchers_local) {
        perror("Failed to allocate client_watchers_local");
        goto cleanup;
    }
    client_info_array_local = (client_info_t**)malloc(g_ptm.max_clients * sizeof(client_info_t*));
    if (!client_info_array_local) {
        perror("Failed to allocate client_info_array_local");
        goto cleanup;
    }
    for (int i = 0; i < g_ptm.max_clients; i++) {
        client_info_array_local[i] = NULL;
    }
    g_ptm.client_fds = client_fds_local;
    g_ptm.client_watchers = client_watchers_local;
    g_ptm.client_info_array = client_info_array_local;

    // Create shared memory for http_client stats using mmap on temp file
    snprintf(g_client_shm_path, sizeof(g_client_shm_path), CLIENT_SHM_PATH);
    fd_client = open(g_client_shm_path, O_CREAT | O_RDWR, 0666);
    if (fd_client == -1) {
        perror("Failed to create temp file for client stats");
        goto cleanup;
    }
    size_t client_stats_size = g_client_stats_size;
    if (ftruncate(fd_client, client_stats_size) == -1) {
        perror("Failed to set size for client stats temp file");
        goto cleanup;
    }
    shm_client_stats_local = mmap(NULL, client_stats_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_client, 0);
    if (shm_client_stats_local == MAP_FAILED) {
        perror("Failed to mmap client stats");
        goto cleanup;
    }
    g_shm_client_stats = shm_client_stats_local;
    memset(g_shm_client_stats, 0, client_stats_size);
    close(fd_client); // Can close fd after mmap
    fd_client = -1; // Mark as closed

    // Create shared memory for http_server stats using mmap on temp file
    snprintf(g_server_shm_path, sizeof(g_server_shm_path), SERVER_SHM_PATH);
    fd_server = open(g_server_shm_path, O_CREAT | O_RDWR, 0666);
    if (fd_server == -1) {
        perror("Failed to create temp file for server stats");
        goto cleanup;
    }
    size_t server_stats_size = g_server_stats_size;
    if (ftruncate(fd_server, server_stats_size) == -1) {
        perror("Failed to set size for server stats temp file");
        goto cleanup;
    }
    shm_server_stats_local = mmap(NULL, server_stats_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_server, 0);
    if (shm_server_stats_local == MAP_FAILED) {
        perror("Failed to mmap server stats");
        goto cleanup;
    }
    g_shm_server_stats = shm_server_stats_local;
    memset(g_shm_server_stats, 0, server_stats_size);
    close(fd_server); // Can close fd after mmap
    fd_server = -1; // Mark as closed

    // For HTTP CLIENTS
    for (int i = 0; i < max_clients_clients; i++) {
        client_info_t *client_info = (client_info_t*)malloc(sizeof(client_info_t));
        if (!client_info) {
            perror("Failed to allocate client_info_t for HTTP client");
            goto cleanup;
        }
        client_info->idx = i;
        client_info->type = CLIENT_TYPE_HTTP_CLIENT;
        client_info->shm_base = (char*)g_shm_client_stats + (i * sizeof(stats_t));
        client_info->shm_size = sizeof(stats_t);
        client_info->check_status_flag = 0; // Initialize check status
        g_ptm.client_info_array[i] = client_info;
    }

    // For HTTP SERVERS
    for (int i = 0; i < max_clients_servers; i++) {
        client_info_t *client_info = (client_info_t*)malloc(sizeof(client_info_t));
        if (!client_info) {
            perror("Failed to allocate client_info_t for HTTP server");
            goto cleanup;
        }
        client_info->idx = i + max_clients_clients; // Adjust index
        client_info->type = CLIENT_TYPE_HTTP_SERVER;
        client_info->shm_base = (char*)g_shm_server_stats + (i * sizeof(stats_t));
        client_info->shm_size = sizeof(stats_t);
        client_info->check_status_flag = 0; // Initialize check status
        g_ptm.client_info_array[i + max_clients_clients] = client_info;
    }

    ptcp_fd_local = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ptcp_fd_local == -1) {
        perror("Failed to create ptcp socket");
        goto cleanup;
    }

    struct sockaddr_un ptcp_addr;
    memset(&ptcp_addr, 0, sizeof(ptcp_addr));
    ptcp_addr.sun_family = AF_UNIX;
    strncpy(ptcp_addr.sun_path, g_ptm.ptcp_socket_path, sizeof(ptcp_addr.sun_path) - 1);

    if (connect(ptcp_fd_local, (struct sockaddr*)&ptcp_addr, sizeof(ptcp_addr)) == -1) {
        perror("Failed to connect to ptcp socket");
        goto cleanup;
    }
    g_ptm.ptcp_fd = ptcp_fd_local;
    printf("Connected to ptcp socket: %s\n", g_ptm.ptcp_socket_path);

    // Start listening on ptm socket
    listen_fd_local = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_local == -1) {
        perror("Failed to create listen socket");
        goto cleanup;
    }

    struct sockaddr_un listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    strncpy(listen_addr.sun_path, g_ptm.ptm_socket_path, sizeof(listen_addr.sun_path) - 1);

    unlink(g_ptm.ptm_socket_path); // Remove if exists
    if (bind(listen_fd_local, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) == -1) {
        perror("Failed to bind listen socket");
        goto cleanup;
    }
    ptm_socket_bound = 1; // Mark that socket path is bound and needs unlinking

    if (listen(listen_fd_local, 5) == -1) {
        perror("Failed to listen on socket");
        goto cleanup;
    }
    g_ptm.listen_fd = listen_fd_local;
    printf("Listening on ptm socket: %s\n", g_ptm.ptm_socket_path);

    // Set up watchers
    ev_io_init(&g_ptm.ptcp_watcher, ptcp_io_cb, g_ptm.ptcp_fd, EV_READ);
    ev_io_start(g_ptm.loop, &g_ptm.ptcp_watcher);

    ev_io_init(&g_ptm.listen_watcher, listen_io_cb, g_ptm.listen_fd, EV_READ);
    ev_io_start(g_ptm.loop, &g_ptm.listen_watcher);

    ev_timer_init(&g_ptm.stats_timer, stats_timer_cb, 1.0, 1.0);

    // Run event loop
    ev_run(g_ptm.loop, 0);

    ret = 0; // If we reach here, the program executed successfully

// Cleanup labels (in reverse order of allocation)
cleanup:
    if (g_ptm.listen_fd != -1) {
        ev_io_stop(g_ptm.loop, &g_ptm.listen_watcher);
        close(g_ptm.listen_fd);
    }
    if (ptm_socket_bound) {
        unlink(g_ptm.ptm_socket_path);
    }

    if (g_ptm.ptcp_fd != -1) {
        ev_io_stop(g_ptm.loop, &g_ptm.ptcp_watcher);
        close(g_ptm.ptcp_fd);
    }

    if (g_ptm.client_info_array) {
        for (int i = 0; i < g_ptm.max_clients; i++) {
            free(g_ptm.client_info_array[i]);
        }
    }

    if (g_shm_server_stats != MAP_FAILED) {
        munmap(g_shm_server_stats, g_server_stats_size);
    }
    unlink(g_server_shm_path); // Always unlink if path was set

    if (fd_server != -1) {
        close(fd_server);
    }

    if (g_shm_client_stats != MAP_FAILED) {
        munmap(g_shm_client_stats, g_client_stats_size);
    }
    unlink(g_client_shm_path); // Always unlink if path was set

    if (fd_client != -1) {
        close(fd_client);
    }
    if (client_info_array_local)
        free(client_info_array_local);
    if (client_watchers_local)
        free(client_watchers_local);
    if (client_fds_local)
        free(client_fds_local);
    if (ptm_socket_path)
        free(ptm_socket_path);
    if (ptcp_socket_path)
        free(ptcp_socket_path);

    return ret;
}

static void forward_to_clients(const char *message, size_t len) {
    for (int i = 0; i < g_ptm.num_clients; i++) {
        printf("Send cmd: %s to client[%d]\n", message, i);
        if (send(g_ptm.client_fds[i], message, len, 0) == -1) {
            perror("Failed to send message to client");
            remove_client(i);
            i--; // Adjust index after removal
        } else {
#if 0
            if (send(g_ptm.client_fds[i], "\n", 1, 0) == -1) {
                perror("Failed to send newline to client");
            }
#endif
        }
    }
}

static void send_aggregated_stats_response(int fd) {
    stats_t aggregated_client_stats;
    aggregate_stats(&aggregated_client_stats, 0); // 0 for client role

    stats_t aggregated_server_stats;
    aggregate_stats(&aggregated_server_stats, 1); // 1 for server role

    // Send client stats
    cJSON *client_response_json = cJSON_CreateObject();
    if (!client_response_json) {
        fprintf(stderr, "Failed to create client response JSON object for aggregated stats\n");
        return;
    }
    cJSON_AddStringToObject(client_response_json, "response_type", "AGGREGATED_CLIENT_STATS"); // New type
    cJSON_AddItemToObject(client_response_json, "aggregated_stats", stats_to_cjson(&aggregated_client_stats));

    char *client_response_str = cJSON_PrintUnformatted(client_response_json);
    if (!client_response_str) {
        fprintf(stderr, "Failed to print aggregated client stats JSON\n");
        cJSON_Delete(client_response_json);
        return;
    }
    if (send(fd, client_response_str, strlen(client_response_str), 0) == -1) {
        perror("Failed to send aggregated client stats to ptcp");
    } else {
        if (send(fd, "\n", 1, 0) == -1) {
            perror("Failed to send newline delimiter after client stats");
        }
    }
    free(client_response_str);
    cJSON_Delete(client_response_json);

    // Send server stats
    cJSON *server_response_json = cJSON_CreateObject();
    if (!server_response_json) {
        fprintf(stderr, "Failed to create server response JSON object for aggregated stats\n");
        return;
    }
    cJSON_AddStringToObject(server_response_json, "response_type", "AGGREGATED_SERVER_STATS"); // New type
    cJSON_AddItemToObject(server_response_json, "aggregated_stats", stats_to_cjson(&aggregated_server_stats));

    char *server_response_str = cJSON_PrintUnformatted(server_response_json);
    if (!server_response_str) {
        fprintf(stderr, "Failed to print aggregated server stats JSON\n");
        cJSON_Delete(server_response_json);
        return;
    }

    if (send(fd, server_response_str, strlen(server_response_str), 0) == -1) {
        perror("Failed to send aggregated server stats to ptcp");
    } else {
        if (send(fd, "\n", 1, 0) == -1) {
            perror("Failed to send newline delimiter after server stats");
        }
    }
    free(server_response_str);
    cJSON_Delete(server_response_json);
}

static void ptcp_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    if (revents & EV_READ) {
        char buffer[4096];
        ssize_t n = recv(g_ptm.ptcp_fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Received from ptcp: %s\n", buffer);

            // Handle plain string commands
            if (strcmp(buffer, "get_stats") == 0) {
                send_aggregated_stats_response(g_ptm.ptcp_fd);
                return;
            } else if (strcmp(buffer, "check") == 0) { // Specific handling for "check"
                // Reset check_status_flag for all clients
                for (int i = 0; i < g_ptm.num_clients; i++) {
                    if (g_ptm.client_info_array[i]) {
                        g_ptm.client_info_array[i]->check_status_flag = 0;
                    }
                }
                forward_to_clients(buffer, n); // Forward "check" to all clients
                printf("Reset client check_status_flags and forwarded 'check' command.\n");
                return; // Command handled
            } else if (strcmp(buffer, "run") == 0) { // Specific handling for "run"
                if (!g_ptm.test_running) {
                    g_ptm.test_running = 1;
                    ev_timer_start(g_ptm.loop, &g_ptm.stats_timer);
                    printf("Test started, starting stats timer.\n");
                }
                forward_to_clients(buffer, n);
                return; // Command handled
            } else if (strcmp(buffer, "stop") == 0) {
                if (g_ptm.test_running) {
                    g_ptm.test_running = 0;
                    ev_timer_stop(g_ptm.loop, &g_ptm.stats_timer);
                    printf("Test stopped, stopping stats timer.\n");
                }
                forward_to_clients(buffer, n);
                return;
            }

        } else if (n == 0) {
            printf("Ptcp connection closed\n");
            if (g_ptm.test_running) {
                g_ptm.test_running = 0;
                ev_timer_stop(g_ptm.loop, &g_ptm.stats_timer);
            }
            ev_io_stop(loop, w);
            close(g_ptm.ptcp_fd);
            g_ptm.ptcp_fd = -1;
        } else {
            perror("Error reading from ptcp");
            if (g_ptm.test_running) {
                g_ptm.test_running = 0;
                ev_timer_stop(g_ptm.loop, &g_ptm.stats_timer);
            }
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

        printf("11111 Accepted client connection, num_clients: %d\n", g_ptm.num_clients);
        g_ptm.client_fds[g_ptm.num_clients] = client_fd;
        ev_io_init(&g_ptm.client_watchers[g_ptm.num_clients], client_io_cb, client_fd, EV_READ);
        g_ptm.client_watchers[g_ptm.num_clients].data = (void*)(uintptr_t)g_ptm.num_clients;
        ev_io_start(loop, &g_ptm.client_watchers[g_ptm.num_clients]);
        g_ptm.num_clients++;
    }
}

static void client_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    int idx = (int)(uintptr_t)w->data;
    client_info_t *current_client_info = g_ptm.client_info_array[idx];

    if (revents & EV_READ) {
        char buffer[4096];
        ssize_t n = recv(g_ptm.client_fds[idx], buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Received from client %d: %s\n", idx, buffer);

            if (strcmp(buffer, "ready") == 0) {
                if (current_client_info) {
                    current_client_info->check_status_flag = 1;
                }

                // Check if all clients are ready
                int all_ready = 1;
                if (g_ptm.num_clients == 0) {
                    all_ready = 0; // If no clients, then not all are ready
                } else {
                    for (int i = 0; i < g_ptm.num_clients; i++) {
                        if (g_ptm.client_info_array[i]->check_status_flag == 0) {
                            all_ready = 0;
                            break;
                        }
                    }
                }
                
                if (all_ready && g_ptm.num_clients > 0) { // Ensure there's at least one client and all are ready
                    // All clients are ready, send a single "ready" message to ptcp
                    const char *response = "ready";
                    if (g_ptm.ptcp_fd != -1) {
                        if (send(g_ptm.ptcp_fd, response, strlen(response), 0) == -1) {
                            perror("Failed to send 'ready' to ptcp after all clients ready");
                        } else {
                            if (send(g_ptm.ptcp_fd, "\n", 1, 0) == -1) {
                                perror("Failed to send newline after 'ready' to ptcp");
                            }
                        }
                    }
                    printf("All clients ready. Sent 'ready' to ptcp.\n");
                }
                // Do NOT forward individual "ready" messages to ptcp
            } else {
                // For messages other than "ready", forward to ptcp
                if (g_ptm.ptcp_fd != -1) {
                    if (send(g_ptm.ptcp_fd, buffer, n, 0) == -1) {
                        perror("Failed to send message to ptcp");
                    } else {
                        if (send(g_ptm.ptcp_fd, "\n", 1, 0) == -1) {
                            perror("Failed to send newline to ptcp");
                        }
                    }
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
    // Get client info before stopping and closing
    client_info_t *removed_client_info = g_ptm.client_info_array[idx];

    ev_io_stop(g_ptm.loop, &g_ptm.client_watchers[idx]);
    close(g_ptm.client_fds[idx]);

    if (g_ptm.test_running) {
        g_ptm.test_running = 0;
        ev_timer_stop(g_ptm.loop, &g_ptm.stats_timer);
        printf("Client %d disconnected, stopping stats timer.\n", idx);
    }

    // Free the removed client's info
    if (removed_client_info) {
        free(removed_client_info);
    }

    // Shift remaining clients
    for (int i = idx; i < g_ptm.num_clients - 1; i++) {
        g_ptm.client_fds[i] = g_ptm.client_fds[i + 1];
        g_ptm.client_watchers[i] = g_ptm.client_watchers[i + 1];
        g_ptm.client_watchers[i].data = (void*)(uintptr_t)i; // Update data pointer
        g_ptm.client_info_array[i] = g_ptm.client_info_array[i+1]; // Shift client_info_array
    }
    // Clear the last element (which is a duplicate after shifting)
    g_ptm.client_info_array[g_ptm.num_clients - 1] = NULL;


    g_ptm.num_clients--;
}
