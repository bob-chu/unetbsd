#ifndef PIPE_CLIENT_H
#define PIPE_CLIENT_H

#include <ev.h>

// Move typedef struct here
typedef struct {
    int fd;
    ev_io io_watcher;
    struct ev_loop *loop;
    char *socket_path;
} pipe_client_t;

void pipe_client_init(struct ev_loop *loop, const char *socket_path, int is_client, int offset_index);
void pipe_client_send_stats(pipe_client_t *client);

#endif // PIPE_CLIENT_H
