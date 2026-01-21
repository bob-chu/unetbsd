#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <ev.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <ctype.h> // Added for isspace

#include "pipe_client.h"
#include "logger.h"
#include "scheduler.h"
#include "metrics.h" // New
#include "deps/cjson/cJSON.h" // New
#include "common.h"
#include "u_tcp_stat.h"

// Forward declaration for the watcher callback
static void pipe_io_cb(struct ev_loop *loop, ev_io *w, int revents);

static pipe_client_t g_pipe_client;

// Forward declaration (no longer static)
void pipe_client_send_stats(pipe_client_t *client);

void pipe_client_init(struct ev_loop *loop, const char *socket_path, int is_client, int offset_index) {
    if (!socket_path) {
        LOG_INFO("No socket path provided for pipe client.");
        fflush(stdout);
        return;
    }

    g_pipe_client.loop = loop;
    g_pipe_client.socket_path = strdup(socket_path); // Duplicate string as it might be argv
    g_pipe_client.is_client = is_client;
    g_pipe_client.offset_index = offset_index;

    g_pipe_client.fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_pipe_client.fd == -1) {
        LOG_ERROR("Failed to create Unix domain socket: %s", strerror(errno));
        fflush(stderr);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_pipe_client.socket_path, sizeof(addr.sun_path) - 1);

    LOG_INFO("Connecting to Unix socket: %s", g_pipe_client.socket_path);
    fflush(stdout);
    if (connect(g_pipe_client.fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        LOG_ERROR("Failed to connect to Unix domain socket %s: %s", g_pipe_client.socket_path, strerror(errno));
        fflush(stderr);
        close(g_pipe_client.fd);
        g_pipe_client.fd = -1; // Corrected
        free(g_pipe_client.socket_path);
        g_pipe_client.socket_path = NULL;
        return;
    }

    LOG_INFO("Successfully connected to Unix socket: %s", g_pipe_client.socket_path);
    fflush(stdout);

    // Initialize and start the ev_io watcher for reading from the pipe
    ev_io_init(&g_pipe_client.io_watcher, pipe_io_cb, g_pipe_client.fd, EV_READ);
    g_pipe_client.io_watcher.data = &g_pipe_client; // Set watcher data
    ev_io_start(g_pipe_client.loop, &g_pipe_client.io_watcher);

    // Connect to shared memory
    char shm_path[256];
    if (is_client) {
        snprintf(shm_path, sizeof(shm_path), CLIENT_SHM_PATH);
    } else {
        snprintf(shm_path, sizeof(shm_path), SERVER_SHM_PATH);
    }

    int fd_shm = open(shm_path, O_RDWR);
    if (fd_shm == -1) {
        LOG_ERROR("Failed to open shared memory file %s: %s", shm_path, strerror(errno));
        fflush(stderr);
        return;
    }

    struct stat st;
    if (fstat(fd_shm, &st) == -1) {
        LOG_ERROR("Failed to stat shared memory file %s: %s", shm_path, strerror(errno));
        close(fd_shm);
        return;
    }
    size_t shm_size = st.st_size;

    void *shm_stats = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd_shm, 0);
    if (shm_stats == MAP_FAILED) {
        LOG_ERROR("Failed to mmap shared memory %s: %s", shm_path, strerror(errno));
        close(fd_shm);
        return;
    }
    close(fd_shm); // Can close fd after mmap

    // Offset into the shared memory array
    g_pipe_client.shm_stats = (stats_t *)shm_stats + offset_index;
    g_pipe_client.shm_size = sizeof(stats_t);
    LOG_INFO("Connected to shared memory: %s, offset_index: %d, size: %zu", shm_path, offset_index, g_pipe_client.shm_size);
    fflush(stdout);

    // Set the stats pointer to use the client's shared memory
    metrics_set_stats(g_pipe_client.shm_stats);
}

void pipe_client_cleanup(void) {
    if (g_pipe_client.shm_stats && g_pipe_client.shm_stats != MAP_FAILED) {
        // Unmap the entire shared memory region
        void *base = (void *)((stats_t *)g_pipe_client.shm_stats - g_pipe_client.offset_index);
        munmap(base, g_pipe_client.shm_size * (g_pipe_client.offset_index + 1)); // Approximate size, adjust if needed
        g_pipe_client.shm_stats = NULL;
    }
}

void pipe_client_send_stats(pipe_client_t *client) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        LOG_ERROR("Failed to create cJSON object for stats.");
        fflush(stderr);
        return;
    }

    // Get current scheduler phase
    const char **phase_names_arr = scheduler_get_phase_names();
    test_phase_t current_phase_enum = scheduler_get_current_phase();
    if (phase_names_arr != NULL && current_phase_enum >= 0 && current_phase_enum < PHASE_FINISHED) {
        cJSON_AddStringToObject(root, "current_phase", phase_names_arr[current_phase_enum]);
    } else {
        cJSON_AddStringToObject(root, "current_phase", "Unknown");
    }

    // Get metrics snapshot (metrics_t)
    metrics_t m_snapshot = metrics_get_snapshot();
    cJSON_AddNumberToObject(root, "metrics_success_count", m_snapshot.success_count);
    cJSON_AddNumberToObject(root, "metrics_failure_count", m_snapshot.failure_count);
    cJSON_AddNumberToObject(root, "metrics_min_latency_ms", m_snapshot.min_latency_ms);
    cJSON_AddNumberToObject(root, "metrics_max_latency_ms", m_snapshot.max_latency_ms);
    cJSON_AddNumberToObject(root, "metrics_avg_latency_ms", m_snapshot.avg_latency_ms);
    cJSON_AddNumberToObject(root, "metrics_total_bytes_sent", m_snapshot.total_bytes_sent);
    cJSON_AddNumberToObject(root, "metrics_total_bytes_received", m_snapshot.total_bytes_received);
    // ... add other relevant metrics_t fields

    // Get stats snapshot (stats_t)
    const stats_t *s_snapshot = scheduler_get_stats();
    cJSON_AddNumberToObject(root, "stats_connections_opened", s_snapshot->connections_opened);
    cJSON_AddNumberToObject(root, "stats_connections_closed", s_snapshot->connections_closed);
    cJSON_AddNumberToObject(root, "stats_requests_sent", s_snapshot->requests_sent);
    cJSON_AddNumberToObject(root, "stats_responses_received", s_snapshot->responses_received);
    cJSON_AddNumberToObject(root, "stats_tcp_concurrent", s_snapshot->tcp_concurrent);
    cJSON_AddNumberToObject(root, "stats_http_conn_fails", s_snapshot->http_conn_fails);
    cJSON_AddNumberToObject(root, "stats_http_req_sent", s_snapshot->http_req_sent);
    cJSON_AddNumberToObject(root, "stats_http_rsp_recv_full", s_snapshot->http_rsp_recv_full);
    cJSON_AddNumberToObject(root, "stats_http_rsp_hdr_overflow", s_snapshot->http_rsp_hdr_overflow);
    cJSON_AddNumberToObject(root, "stats_http_rsp_hdr_parse_err", s_snapshot->http_rsp_hdr_parse_err);
    cJSON_AddNumberToObject(root, "stats_http_rsp_body_send_err", s_snapshot->http_rsp_body_send_err);
    cJSON_AddNumberToObject(root, "stats_http_rsp_hdr_send_err", s_snapshot->http_rsp_hdr_send_err);
    cJSON_AddNumberToObject(root, "stats_tcp_bytes_sent", s_snapshot->tcp_bytes_sent);
    cJSON_AddNumberToObject(root, "stats_tcp_bytes_received", s_snapshot->tcp_bytes_received);

    uint64_t netbsd_stats[UNETBSD_TCP_NSTATS];
    size_t netbsd_stats_len = UNETBSD_TCP_NSTATS;
    if (unetbsd_get_tcp_stats(netbsd_stats, &netbsd_stats_len) == 0) {
        for (int i = 0; i < UNETBSD_TCP_NSTATS; i++) {
            const char *name = unetbsd_get_tcp_stat_name(i);
            if (name) {
                char full_name[128];
                snprintf(full_name, sizeof(full_name), "netbsd_tcp_%s", name);
                for (char *p = full_name; *p; p++) {
                    if (*p == ' ') *p = '_';
                    if (*p == '#') *p = 'n';
                }
                cJSON_AddNumberToObject(root, full_name, (double)netbsd_stats[i]);
            }
        }
    }

    char *json_string = cJSON_PrintUnformatted(root);
    if (json_string == NULL) {
        LOG_ERROR("Failed to print cJSON object for stats.");
        fflush(stderr);
        cJSON_Delete(root);
        return;
    }

    send(client->fd, json_string, strlen(json_string), 0);
    LOG_INFO("Sent statistics JSON: %s", json_string);
    fflush(stdout);

    cJSON_Delete(root);
    free(json_string);
}

static void pipe_io_cb(struct ev_loop *loop, ev_io *w, int revents) {
    pipe_client_t *client = (pipe_client_t*)w->data; // Using w->data to store client_t instance

    if (revents & EV_READ) {
        char buffer[256];
        ssize_t n = recv(client->fd, buffer, sizeof(buffer) - 1, 0);
        if (n > 0) {
            buffer[n] = '\0';
            // Trim trailing whitespace (including newline)
            for (int i = n - 1; i >= 0; i--) {
                if (isspace((unsigned char)buffer[i])) {
                    buffer[i] = '\0';
                } else {
                    break;
                }
            }
            LOG_INFO("Received from pipe: %s", buffer);
            fflush(stdout);

            if (strcmp(buffer, "run") == 0) {
                LOG_INFO("Received 'run' command. Unpausing scheduler.");
                fflush(stdout);
                scheduler_set_paused(false);
            } else if (strcmp(buffer, "check") == 0) {
                LOG_INFO("Received 'check' command. Reporting ready status.");
                fflush(stdout);
                const char *response = "ready\n";
                if (send(client->fd, response, strlen(response), 0) == -1) {
                    LOG_ERROR("Failed to send 'ready' to master: %s", strerror(errno));
                } else {
                    LOG_INFO("Sent 'ready' to master.");
                }
            } else if (strcmp(buffer, "get_stats") == 0) { // New: handle get_stats command
                LOG_INFO("Received 'get_stats' command. Sending statistics.");
                fflush(stdout);
                pipe_client_send_stats(client);
            }
        } else if (n == 0) {
            LOG_INFO("Pipe server closed connection.");
            ev_io_stop(loop, &client->io_watcher);
            close(client->fd);
            client->fd = -1;
            free(client->socket_path);
            client->socket_path = NULL;
            pipe_client_cleanup();
        } else {
            LOG_ERROR("Error reading from pipe: %s", strerror(errno));
            ev_io_stop(loop, &client->io_watcher);
            close(client->fd);
            client->fd = -1;
            free(client->socket_path);
            client->socket_path = NULL;
            pipe_client_cleanup();
        }
    }
}
