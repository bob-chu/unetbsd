#ifndef _U_FD_H_
#define _U_FD_H_

#include "u_socket.h"

#define MAX_FD 65536  // Support up to 65K concurrent connections

extern int fd_stack[MAX_FD];
extern int fd_stack_top;

void fd_table_init(void);
int u_fd_alloc(struct netbsd_handle *nh);
struct netbsd_handle *fd_get(int fd);
void u_fd_set(int fd, struct netbsd_handle *nh);  // ADD MISSING DECLARATION!
void u_fd_free(int fd);
void fd_table_free(void);

#endif /* _U_FD_H_ */
