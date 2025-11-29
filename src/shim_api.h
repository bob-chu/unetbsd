#ifndef _SHIM_API_H_
#define _SHIM_API_H_

#include <sys/socket.h>
#include <stdint.h> // For intptr_t

struct netbsd_handle; // Forward declaration

int shim_socket(int domain, int type, int protocol);
int shim_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int shim_listen(int sockfd, int backlog);
int shim_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int shim_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t shim_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t shim_recv(int sockfd, void *buf, size_t len, int flags);
int shim_close(int sockfd);

#endif /* _SHIM_API_H_ */
