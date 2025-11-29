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
    // Initialize the stack with available FDs, starting from 3
    for (int i = MAX_FD - 1; i >= 3; i--) {
        fd_stack[fd_stack_top++] = i;
    }
}

int u_fd_alloc(struct netbsd_handle *nh)
{
    if (fd_stack_top == 0) {
        return -1; // No available fd
    }

    int fd = fd_stack[--fd_stack_top];
    fd_table[fd] = nh;
    return fd;
}

struct netbsd_handle *fd_get(int fd)
{
    if (fd < 0 || fd >= MAX_FD) {
        return NULL;
    }
    return fd_table[fd];
}

void u_fd_free(int fd)
{
    if (fd >= 0 && fd < MAX_FD) {
        fd_table[fd] = NULL;
        fd_stack[fd_stack_top++] = fd;
    }
}

void fd_table_free(void)
{
    // This function is not strictly necessary if the handles are managed elsewhere,
    // but it's good practice to have a way to clean up the table.
    for (int i = 0; i < MAX_FD; i++) {
        if (fd_table[i] != NULL) {
            // The caller is responsible for freeing the netbsd_handle itself.
            fd_table[i] = NULL;
        }
    }
    // Re-initialize the stack
    fd_table_init();
}
