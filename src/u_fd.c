#include "u_fd.h"
#include <stddef.h>

static struct netbsd_handle *fd_table[MAX_FD];
int fd_stack[MAX_FD];
int fd_stack_top;

void fd_table_init(void)
{
    for (int i = 0; i < MAX_FD; i++) {
        fd_table[i] = NULL;
    }

    fd_stack_top = 0;
    // Use full table: 0-65535 (shim adds 1024 offset when returning to app)
    for (int i = MAX_FD - 1; i >= 0; i--) {
        fd_stack[fd_stack_top++] = i;
    }
}

int u_fd_alloc(struct netbsd_handle *nh)
{
    while (fd_stack_top > 0) {
        int fd = fd_stack[--fd_stack_top];
        if (fd_table[fd] == NULL) {
            fd_table[fd] = nh;
            return fd;
        }
        // fd is already in use (e.g. manually set by u_fd_set), try next
    }
    return -1; // No available fd
}

struct netbsd_handle *fd_get(int fd)
{
    if (fd < 0 || fd >= MAX_FD) {
        return NULL;
    }
    return fd_table[fd];
}

// Direct FD table set - allows bypassing fd_stack allocation
void u_fd_set(int fd, struct netbsd_handle *nh)
{
    if (fd >= 0 && fd < MAX_FD) {
        fd_table[fd] = nh;
    }
}

void u_fd_free(int fd)
{
    if (fd > 0 && fd < MAX_FD) {
        // Check for double-free
        if (fd_table[fd] == NULL) {
            return;  // Already freed
        }
        
        fd_table[fd] = NULL;
        
        // Check for stack overflow
        if (fd_stack_top >= MAX_FD) {
            return;  // Error
        }
        
        fd_stack[fd_stack_top++] = fd;
    }
}

void fd_table_free(void)
{
    for (int i = 0; i < MAX_FD; i++) {
        if (fd_table[i] != NULL) {
            fd_table[i] = NULL;
        }
    }
    fd_table_init();
}
