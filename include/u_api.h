#ifndef U_API_H
#define U_API_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * struct kevent matching NetBSD definition 
 * (from sys/event.h)
 */
struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	uint32_t	filter;		/* filter for event */
	uint32_t	flags;		/* action flags for kqueue */
	uint32_t	fflags;		/* filter-specific flags */
	int64_t		data;		/* filter-specific data */
	void		*udata;		/* opaque user data identifier */
	uint64_t	ext[4];		/* extensions */
};

struct timespec;

/* Native Linux-like Socket API (returns result or -1 and sets errno) */
int u_socket(int domain, int type, int protocol);
int u_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int u_listen(int sockfd, int backlog);
int u_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int u_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t u_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen);
ssize_t u_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen);
int u_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int u_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int u_close(int fd);
int u_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int u_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int u_shutdown(int sockfd, int how);
ssize_t u_read(int fd, void *buf, size_t count);
ssize_t u_write(int fd, const void *buf, size_t count);
int u_ioctl(int fd, unsigned long request, void *argp);
int u_fcntl(int fd, int cmd, void *arg);
int u_poll(struct pollfd *fds, nfds_t nfds, int timeout);

/* Event API (kqueue) */
int u_kqueue(void);
int u_kevent(int kq, const struct kevent *changelist, int nchanges,
             struct kevent *eventlist, int nevents,
             const struct timespec *timeout);

/* Helper functions */
int u_set_nonblocking(int s, int nonblocking);
int u_is_nonblocking(int s);
int u_is_connecting(int s);
int u_is_connected(int s);
int u_socket_error(int s);

#ifdef __cplusplus
}
#endif

#endif /* U_API_H */
