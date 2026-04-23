/*
 * u_syscall.c - POSIX-like socket API using NetBSD's native file descriptor layer
 *
 * This file implements the u_* functions declared in u_api.h.
 * It bridges directly to NetBSD's kernel infrastructure:
 *   - kern_descrip.c: fd_alloc, fd_getfile, fd_getsock, fd_close, fd_allocfile, fd_affix
 *   - sys_socket.c:   socketops (soo_read, soo_write, soo_poll, soo_close, soo_kqfilter)
 *   - kern_event.c:   kqueue1, kevent1
 *   - uipc_socket.c:  socreate, sobind, solisten, soconnect, soaccept, soclose
 *
 * Compiled with -D_KERNEL as part of libnetbsdstack.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/event.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>

/* Forward declarations from NetBSD kernel */
extern const struct fileops socketops;
extern int kevent1(register_t *retval, int fd,
	const struct kevent *changelist, size_t nchanges,
	struct kevent *eventlist, size_t nevents,
	const struct timespec *timeout,
	const struct kevent_ops *keops);
extern int kevent_fetch_changes(void *ctx, const struct kevent *changelist,
    struct kevent *changes, size_t index, int n);
extern int kevent_put_events(void *ctx, struct kevent *events,
    struct kevent *eventlist, size_t index, int n);

/* ============================================================
 * File descriptor initialization
 * ============================================================ */

static int u_fd_initialized = 0;

/*
 * Initialize the file descriptor table for our process.
 * Must be called before any u_* functions.
 */
void
u_fd_init(void)
{
	if (u_fd_initialized)
		return;

	/* fd_sys_init() creates pool caches for file_t and filedesc_t */
	fd_sys_init();

	/* Initialize filedesc0 - this sets up the built-in fd table,
	 * bitmaps, and mutex. Passing &filedesc0 tells fd_init to
	 * initialize it in-place rather than allocating. */
	fd_init(&filedesc0);

	/* Make sure curlwp's l_fd points to filedesc0 */
	curlwp->l_fd = &filedesc0;
	curproc->p_fd = &filedesc0;

	/* Set resource limit for max open files */
	curproc->p_rlimit[RLIMIT_NOFILE].rlim_cur = 65536;
	curproc->p_rlimit[RLIMIT_NOFILE].rlim_max = 65536;

	u_fd_initialized = 1;
}

/* ============================================================
 * Sockaddr translation: Linux → NetBSD
 *
 * Linux sockaddr layout:  [sa_family (2 bytes)] [sa_data...]
 * NetBSD sockaddr layout: [sa_len (1 byte)] [sa_family (1 byte)] [sa_data...]
 *
 * Since the test app is compiled with Linux userspace headers but the
 * kernel expects NetBSD-format sockaddrs, we need to translate.
 * ============================================================ */

static int
u_sockargs(struct mbuf **mp, const struct sockaddr *addr, socklen_t addrlen)
{
	struct mbuf *m;
	struct sockaddr *sa;
	uint16_t linux_family;
	int error;

	/* Get the Linux family value before sockargs overwrites it */
	linux_family = *(const uint16_t *)addr;

	error = sockargs(mp, addr, addrlen, UIO_USERSPACE, MT_SONAME);
	if (error)
		return error;

	/* Fix up the sockaddr: sockargs set sa_len = addrlen,
	 * but clobbered sa_family. Restore it from the Linux 2-byte field. */
	m = *mp;
	sa = mtod(m, struct sockaddr *);
	sa->sa_len = addrlen;
	sa->sa_family = (sa_family_t)linux_family;

	return 0;
}

/* ============================================================
 * Socket API
 * ============================================================ */

extern int u_set_errno(int nb_error);
extern ssize_t u_set_errno_ssize(int nb_error);

/*
 * u_socket - Create a socket and return a file descriptor.
 * Returns fd on success, negative error on failure.
 */
int
u_socket(int domain, int type, int protocol)
{
	struct socket *so;
	file_t *fp;
	int fd, error;

	if (!u_fd_initialized)
		u_fd_init();

	softint_run();

	/* Create the socket */
	error = socreate(domain, &so, type, protocol, curlwp, NULL);
	if (error)
		return u_set_errno(error);

	/* Allocate a file descriptor */
	error = fd_allocfile(&fp, &fd);
	if (error) {
		soclose(so);
		return u_set_errno(error);
	}

	/* Set up the file structure for socket operations */
	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_SOCKET;
	fp->f_ops = &socketops;
	fp->f_socket = so;

	/* Make the fd visible */
	fd_affix(curproc, fp, fd);

	return fd;
}

/*
 * u_bind - Bind a socket to an address.
 */
int
u_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct socket *so;
	struct mbuf *nam;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	softint_run();

	error = u_sockargs(&nam, name, namelen);
	if (error) {
		fd_putfile(s);
		return u_set_errno(error);
	}

	error = sobind(so, mtod(nam, struct sockaddr *), curlwp);

	m_freem(nam);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_listen - Listen for connections.
 */
int
u_listen(int s, int backlog)
{
	struct socket *so;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	error = solisten(so, backlog, curlwp);

	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_accept - Accept a connection.
 */
int
u_accept(int s, struct sockaddr *name, socklen_t *namelen)
{
	struct socket *so, *so2;
	struct mbuf *nam;
	file_t *fp;
	int fd, error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	softint_run();

	/* Allocate a new fd for the accepted connection */
	error = fd_allocfile(&fp, &fd);
	if (error) {
		fd_putfile(s);
		return u_set_errno(error);
	}

	nam = m_get(M_WAIT, MT_SONAME);
	if (nam == NULL) {
		fd_abort(curproc, fp, fd);
		fd_putfile(s);
		return u_set_errno(ENOMEM);
	}
	nam->m_len = 0;

	solock(so);

	/* Check for pending connections */
	if ((so->so_options & SO_ACCEPTCONN) == 0) {
		sounlock(so);
		m_freem(nam);
		fd_abort(curproc, fp, fd);
		fd_putfile(s);
		return u_set_errno(EINVAL);
	}

	if ((so->so_state & SS_NBIO) && so->so_qlen == 0) {
		sounlock(so);
		m_freem(nam);
		fd_abort(curproc, fp, fd);
		fd_putfile(s);
		return u_set_errno(EWOULDBLOCK);
	}

	while (so->so_qlen == 0 && so->so_error == 0) {
		if (so->so_state & SS_CANTRCVMORE) {
			so->so_error = ECONNABORTED;
			break;
		}
		/* In our single-threaded model, if no connection pending, return EAGAIN */
		sounlock(so);
		m_freem(nam);
		fd_abort(curproc, fp, fd);
		fd_putfile(s);
		return u_set_errno(EAGAIN);
	}

	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		sounlock(so);
		m_freem(nam);
		fd_abort(curproc, fp, fd);
		fd_putfile(s);
		return u_set_errno(error);
	}

	/* Dequeue the first connection */
	so2 = TAILQ_FIRST(&so->so_q);
	if (soqremque(so2, 1) == 0)
		panic("u_accept: soqremque failed");

	/* Set up the new file structure */
	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_SOCKET;
	fp->f_ops = &socketops;
	fp->f_socket = so2;

	sounlock(so);

	/* Get peer address if requested */
	if (name) {
		solock(so2);
		error = (*so2->so_proto->pr_usrreqs->pr_accept)(so2, mtod(nam, struct sockaddr *));
		sounlock(so2);
		if (error == 0) {
			struct sockaddr *sa = mtod(nam, struct sockaddr *);
			socklen_t sa_len = sa->sa_len;
			if (namelen && *namelen < sa_len)
				sa_len = *namelen;
			memcpy(name, sa, sa_len);
			if (namelen)
				*namelen = sa_len;
		}
	}

	m_freem(nam);

	/* Make the new fd visible */
	fd_affix(curproc, fp, fd);

	fd_putfile(s);
	return fd;
}

/*
 * u_connect - Connect a socket to an address.
 */
int
u_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	struct socket *so;
	struct mbuf *nam;
	int error;

	error = fd_getsock(s, &so);

	softint_run();
	if (error)
		return u_set_errno(error);

	error = u_sockargs(&nam, name, namelen);
	if (error) {
		fd_putfile(s);
		return u_set_errno(error);
	}

	solock(so);
	error = soconnect(so, mtod(nam, struct sockaddr *), curlwp);
	if (error)
		goto out;

	/* If non-blocking, return EINPROGRESS */
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		error = EINPROGRESS;
		goto out;
	}

out:
	sounlock(so);
	m_freem(nam);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_read - Read from a file descriptor (socket).
 */
ssize_t
u_read(int fd, void *buf, size_t nbyte)
{
	file_t *fp;
	struct uio auio;
	struct iovec aiov;
	int error;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return u_set_errno_ssize(EBADF);

	aiov.iov_base = buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_offset = 0;
	auio.uio_vmspace = NULL;

	error = (*fp->f_ops->fo_read)(fp, &auio.uio_offset, &auio,
	    fp->f_cred, 0);

	fd_putfile(fd);

	if (error)
		return u_set_errno(error);

	return nbyte - auio.uio_resid;
}

/*
 * u_write - Write to a file descriptor (socket).
 */
ssize_t
u_write(int fd, const void *buf, size_t nbyte)
{
	file_t *fp;
	struct uio auio;
	struct iovec aiov;
	int error;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return u_set_errno_ssize(EBADF);

	aiov.iov_base = __UNCONST(buf);
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_WRITE;
	auio.uio_offset = 0;
	auio.uio_vmspace = NULL;

	error = (*fp->f_ops->fo_write)(fp, &auio.uio_offset, &auio,
	    fp->f_cred, 0);

	fd_putfile(fd);

	if (error)
		return u_set_errno(error);

	return nbyte - auio.uio_resid;
}

/*
 * u_recvfrom - Receive data from a socket.
 */
ssize_t
u_recvfrom(int s, void *buf, size_t len, int flags,
    struct sockaddr *from, socklen_t *fromlen)
{
	struct socket *so;
	struct mbuf *m_from = NULL;
	struct uio auio;
	struct iovec aiov;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	aiov.iov_base = buf;
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_rw = UIO_READ;
	auio.uio_offset = 0;
	auio.uio_vmspace = NULL;

	error = (*so->so_receive)(so, from ? &m_from : NULL, &auio,
	    NULL, NULL, &flags);

	if (error == 0 && from && m_from) {
		struct sockaddr *sa = mtod(m_from, struct sockaddr *);
		socklen_t sa_len = sa->sa_len;
		if (fromlen && *fromlen < sa_len)
			sa_len = *fromlen;
		memcpy(from, sa, sa_len);
		if (fromlen)
			*fromlen = sa_len;
	}
	if (m_from)
		m_freem(m_from);

	fd_putfile(s);

	if (error)
		return u_set_errno(error);

	return len - auio.uio_resid;
}

/*
 * u_sendto - Send data to a socket.
 */
ssize_t
u_sendto(int s, const void *buf, size_t len, int flags,
    const struct sockaddr *to, socklen_t tolen)
{
	struct socket *so;
	struct mbuf *nam = NULL;
	struct uio auio;
	struct iovec aiov;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	if (to) {
		error = u_sockargs(&nam, to, tolen);
		if (error) {
			fd_putfile(s);
			return u_set_errno_ssize(error);
		}
	}

	aiov.iov_base = __UNCONST(buf);
	aiov.iov_len = len;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;
	auio.uio_rw = UIO_WRITE;
	auio.uio_offset = 0;
	auio.uio_vmspace = NULL;

	error = (*so->so_send)(so, nam ? mtod(nam, struct sockaddr *) : NULL, &auio, NULL, NULL, flags, curlwp);

	if (nam)
		m_freem(nam);
	fd_putfile(s);

	if (error)
		return u_set_errno(error);

	return len - auio.uio_resid;
}

/*
 * u_setsockopt / u_getsockopt
 */
int
u_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	struct socket *so;
	struct sockopt sopt;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	sockopt_init(&sopt, level, optname, optlen);
	if (optval && optlen > 0)
		memcpy(sopt.sopt_data, optval, optlen);

	solock(so);
	error = sosetopt(so, &sopt);
	sounlock(so);

	sockopt_destroy(&sopt);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

int
u_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	struct socket *so;
	struct sockopt sopt;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	sockopt_init(&sopt, level, optname, 0);

	solock(so);
	error = sogetopt(so, &sopt);
	sounlock(so);

	if (error == 0 && optval && optlen) {
		size_t len = *optlen;
		if (len > sopt.sopt_retsize)
			len = sopt.sopt_retsize;
		memcpy(optval, sopt.sopt_data, len);
		*optlen = len;
	}

	sockopt_destroy(&sopt);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_shutdown - Shutdown a socket.
 */
int
u_shutdown(int s, int how)
{
	struct socket *so;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	solock(so);
	error = soshutdown(so, how);
	sounlock(so);

	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_close - Close a file descriptor.
 */
int
u_close(int fd)
{
	file_t *fp;
	int error;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return u_set_errno(EBADF);

	error = fd_close(fd);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_getpeername / u_getsockname
 */
int
u_getpeername(int s, struct sockaddr *asa, socklen_t *alen)
{
	struct socket *so;
	struct mbuf *m;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	m = m_get(M_WAIT, MT_SONAME);
	if (m == NULL) {
		fd_putfile(s);
		return u_set_errno(ENOMEM);
	}

	solock(so);
	error = (*so->so_proto->pr_usrreqs->pr_peeraddr)(so, mtod(m, struct sockaddr *));
	sounlock(so);

	if (error == 0) {
		struct sockaddr *sa = mtod(m, struct sockaddr *);
		socklen_t sa_len = sa->sa_len;
		if (alen && *alen < sa_len)
			sa_len = *alen;
		memcpy(asa, sa, sa_len);
		if (alen)
			*alen = sa_len;
	}

	m_freem(m);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

int
u_getsockname(int s, struct sockaddr *asa, socklen_t *alen)
{
	struct socket *so;
	struct mbuf *m;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	m = m_get(M_WAIT, MT_SONAME);
	if (m == NULL) {
		fd_putfile(s);
		return u_set_errno(ENOMEM);
	}

	solock(so);
	error = (*so->so_proto->pr_usrreqs->pr_sockaddr)(so, mtod(m, struct sockaddr *));
	sounlock(so);

	if (error == 0) {
		struct sockaddr *sa = mtod(m, struct sockaddr *);
		socklen_t sa_len = sa->sa_len;
		if (alen && *alen < sa_len)
			sa_len = *alen;
		memcpy(asa, sa, sa_len);
		if (alen)
			*alen = sa_len;
	}

	m_freem(m);
	fd_putfile(s);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_ioctl - Socket ioctl.
 */
int
u_ioctl(int fd, unsigned long com, void *data)
{
	file_t *fp;
	int error;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return u_set_errno(EBADF);

	error = (*fp->f_ops->fo_ioctl)(fp, com, data);

	fd_putfile(fd);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_fcntl - File control for socket fds.
 */
int
u_fcntl(int fd, int cmd, void *arg)
{
	file_t *fp;
	int error = 0;

	fp = fd_getfile(fd);
	if (fp == NULL)
		return u_set_errno(EBADF);

	switch (cmd) {
	case F_GETFL:
		fd_putfile(fd);
		return fp->f_flag;
	case F_SETFL:
		fp->f_flag = (fp->f_flag & ~FCNTLFLAGS) |
		    ((uintptr_t)arg & FCNTLFLAGS);
		/* Also update socket non-blocking state */
		if (fp->f_type == DTYPE_SOCKET && fp->f_socket) {
			struct socket *so = fp->f_socket;
			solock(so);
			if ((uintptr_t)arg & FNONBLOCK)
				so->so_state |= SS_NBIO;
			else
				so->so_state &= ~SS_NBIO;
			sounlock(so);
		}
		break;
	default:
		error = (*fp->f_ops->fo_fcntl)(fp, cmd, arg);
		break;
	}

	fd_putfile(fd);
	return error ? u_set_errno(error) : 0;
}

/*
 * u_poll - Poll file descriptors.
 */
int
u_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;
	int nready = 0;

	for (i = 0; i < nfds; i++) {
		file_t *fp;
		int events;

		fds[i].revents = 0;
		if (fds[i].fd < 0)
			continue;

		fp = fd_getfile(fds[i].fd);
		if (fp == NULL) {
			fds[i].revents = POLLNVAL;
			nready++;
			continue;
		}

		events = (*fp->f_ops->fo_poll)(fp, fds[i].events);
		fd_putfile(fds[i].fd);

		if (events) {
			fds[i].revents = events;
			nready++;
		}
	}

	return nready;
}

/* ============================================================
 * Helper functions
 * ============================================================ */

int
u_set_nonblocking(int s, int nonblocking)
{
	struct socket *so;
	int error;

	error = fd_getsock(s, &so);
	if (error)
		return u_set_errno(error);

	solock(so);
	if (nonblocking)
		so->so_state |= SS_NBIO;
	else
		so->so_state &= ~SS_NBIO;
	sounlock(so);

	/* Also update file flags */
	file_t *fp = fd_getfile(s);
	if (fp) {
		if (nonblocking)
			fp->f_flag |= FNONBLOCK;
		else
			fp->f_flag &= ~FNONBLOCK;
		fd_putfile(s);
	}

	fd_putfile(s);
	return 0;
}

int
u_is_nonblocking(int s)
{
	struct socket *so;
	int error, nb;

	error = fd_getsock(s, &so);
	if (error)
		return 0;

	nb = (so->so_state & SS_NBIO) ? 1 : 0;
	fd_putfile(s);
	return nb;
}

int
u_is_connecting(int s)
{
	struct socket *so;
	int error, c;

	error = fd_getsock(s, &so);
	if (error)
		return 0;

	c = (so->so_state & SS_ISCONNECTING) ? 1 : 0;
	fd_putfile(s);
	return c;
}

int
u_is_connected(int s)
{
	struct socket *so;
	int error, c;

	error = fd_getsock(s, &so);
	if (error)
		return 0;

	c = (so->so_state & SS_ISCONNECTED) ? 1 : 0;
	fd_putfile(s);
	return c;
}

int
u_socket_error(int s)
{
	struct socket *so;
	int error, serr;

	error = fd_getsock(s, &so);
	if (error)
		return error;

	serr = so->so_error;
	so->so_error = 0;
	fd_putfile(s);
	return serr;
}

/* ============================================================
 * kqueue API
 * ============================================================ */

/*
 * u_kqueue - Create a kqueue.
 * Calls kqueue1() from kern_event.c via sys_kqueue.
 */
int
u_kqueue(void)
{
	register_t retval;
	int error;

	if (!u_fd_initialized)
		u_fd_init();

	error = sys_kqueue(curlwp, NULL, &retval);
	if (error)
		return u_set_errno(error);

	return (int)retval;
}

/*
 * u_kevent - Register/retrieve kqueue events.
 * Calls kevent1() from kern_event.c.
 */
static const struct kevent_ops u_kevent_ops = {
	.keo_private = NULL,
	.keo_fetch_timeout = copyin,
	.keo_fetch_changes = kevent_fetch_changes,
	.keo_put_events = kevent_put_events,
};

int
u_kevent(int kq, const struct kevent *changelist, int nchanges,
    struct kevent *eventlist, int nevents,
    const struct timespec *timeout)
{
	register_t retval = 0;
	int error;

	softint_run();

	error = kevent1(&retval, kq,
	    changelist, nchanges,
	    eventlist, nevents,
	    timeout, &u_kevent_ops);

	if (error)
		return u_set_errno(error);

	return (int)retval;
}
