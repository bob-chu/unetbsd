/*
 * This file provides a helper to set the host errno and return -1.
 * It is designed to be compatible with both kernel-mode (-D_KERNEL -nostdinc)
 * and user-mode build flags.
 */

#ifdef _KERNEL
/* In kernel mode, we don't have <errno.h> or <sys/types.h> from the host.
 * We manually declare the glibc errno location function and constants. */
extern int *__errno_location(void);
#define errno (*__errno_location())
typedef long ssize_t;

#define   LX_ENOENT           2
#define   LX_EIO              5
#define   LX_EBADF            9
#define   LX_EAGAIN          11
#define   LX_ENOMEM          12
#define   LX_EACCES          13
#define   LX_EFAULT          14
#define   LX_EEXIST          17
#define   LX_ENODEV          19
#define   LX_EINVAL          22
#define   LX_ENFILE          23
#define   LX_EMFILE          24
#define   LX_EPIPE           32
#define   LX_EOPNOTSUPP      95
#define   LX_EAFNOSUPPORT    97
#define   LX_EADDRINUSE      98
#define   LX_EADDRNOTAVAIL   99
#define   LX_ENETDOWN        100
#define   LX_ENETUNREACH     101
#define   LX_ECONNRESET      104
#define   LX_EISCONN         106
#define   LX_ENOTCONN        107
#define   LX_ETIMEDOUT       110
#define   LX_ECONNREFUSED    111
#define   LX_EHOSTUNREACH    113
#define   LX_EINPROGRESS     115
#else
#include <errno.h>
#include <sys/types.h>
#define LX_ENOENT       ENOENT
#define LX_EIO          EIO
#define LX_EBADF        EBADF
#define LX_EAGAIN       EAGAIN
#define LX_ENOMEM       ENOMEM
#define LX_EACCES       EACCES
#define LX_EFAULT       EFAULT
#define LX_EEXIST       EEXIST
#define LX_ENODEV       ENODEV
#define LX_EINVAL       EINVAL
#define LX_ENFILE       ENFILE
#define LX_EMFILE       EMFILE
#define LX_EPIPE        EPIPE
#define LX_EOPNOTSUPP   EOPNOTSUPP
#define LX_EAFNOSUPPORT EAFNOSUPPORT
#define LX_EADDRINUSE   EADDRINUSE
#define LX_EADDRNOTAVAIL EADDRNOTAVAIL
#define LX_ENETDOWN     ENETDOWN
#define LX_ENETUNREACH  ENETUNREACH
#define LX_ECONNRESET   ECONNRESET
#define LX_EISCONN      EISCONN
#define LX_ENOTCONN     ENOTCONN
#define LX_ETIMEDOUT    ETIMEDOUT
#define LX_ECONNREFUSED ECONNREFUSED
#define LX_EHOSTUNREACH EHOSTUNREACH
#define LX_EINPROGRESS  EINPROGRESS
#endif

#include "u_api.h"

int u_set_errno(int nb_error) {
    int host_error;

    if (nb_error == 0)
        return 0;

    /* Translate NetBSD errno to Linux errno */
    switch (nb_error) {
        case 0:  host_error = 0; break;
        case 2:  host_error = LX_ENOENT; break;
        case 5:  host_error = LX_EIO; break;
        case 9:  host_error = LX_EBADF; break;
        case 11: host_error = LX_EAGAIN; break; 
        case 12: host_error = LX_ENOMEM; break;
        case 13: host_error = LX_EACCES; break;
        case 14: host_error = LX_EFAULT; break;
        case 17: host_error = LX_EEXIST; break;
        case 19: host_error = LX_ENODEV; break;
        case 22: host_error = LX_EINVAL; break;
        case 23: host_error = LX_ENFILE; break;
        case 24: host_error = LX_EMFILE; break;
        case 32: host_error = LX_EPIPE; break;
        case 35: host_error = LX_EAGAIN; break; /* Current NetBSD EAGAIN */
        case 36: host_error = LX_EINPROGRESS; break;
        case 42: host_error = 92; break; /* NetBSD ENOPROTOOPT (42) -> Linux ENOPROTOOPT (92) */
        case 45: host_error = LX_EOPNOTSUPP; break;
        case 47: host_error = LX_EAFNOSUPPORT; break;
        case 48: host_error = LX_EADDRINUSE; break;
        case 49: host_error = LX_EADDRNOTAVAIL; break;
        case 50: host_error = LX_ENETDOWN; break;
        case 51: host_error = LX_ENETUNREACH; break;
        case 54: host_error = LX_ECONNRESET; break;
        case 56: host_error = LX_EISCONN; break;
        case 57: host_error = LX_ENOTCONN; break;
        case 60: host_error = LX_ETIMEDOUT; break;
        case 61: host_error = LX_ECONNREFUSED; break;
        case 65: host_error = LX_EHOSTUNREACH; break;
        default: host_error = nb_error; break;
    }

    errno = host_error;
    return -1;
}

ssize_t u_set_errno_ssize(int nb_error) {
    u_set_errno(nb_error);
    return -1;
}
