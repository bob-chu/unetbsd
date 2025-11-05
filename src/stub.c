#include <sys/param.h>
#include <sys/systm.h>
#include <sys/percpu.h>
#include <sys/once.h>
#include <sys/thmap.h>

#include <sys/kernel.h>
#include <sys/xcall.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/device.h>
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/acct.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/mbuf.h>
#include <ufs/ufs/quota.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mutex.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_stats.h>
#include <netinet/in.h>


struct cpu_info cpu0 = {0};
struct lwp	*curlwp;

#if 1
#ifdef curlwp
#undef curlwp
#endif
#define curlwp stub_curlwp()
#endif
/*
 * sys/kern/uipc_mbuf.c global variable
 */

const int msize = 512;
const int mclbytes = 2048;

#define PHYSMEM 1048576*256
unsigned long physmem = PHYSMEM;
unsigned long nkmempages = PHYSMEM/2; /* from le chapeau */
#undef PHYSMEM

int nmbclusters = 4096;
int mblowat = 256;
int mcllowat = 64;


/*
 * time related
 */
time_t time_update = 0;
volatile struct	timeval my_time;
volatile time_t time__uptime;
volatile time_t time__second;

extern void exit(int) __attribute__ ((__noreturn__));
extern int gettimeofday(struct timeval *, void*);

/*
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t
strlcpy(char * __restrict dst, const char * __restrict src, size_t dsize)
{
	const char *osrc = src;
	size_t nleft = dsize;

	/* Copy as many bytes as will fit. */
	if (nleft != 0) {
		while (--nleft != 0) {
			if ((*dst++ = *src++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src. */
	if (nleft == 0) {
		if (dsize != 0)
			*dst = '\0';		/* NUL-terminate dst */
		while (*src++)
			;
	}

	return(src - osrc - 1);	/* count does not include NUL */
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}


int splraise(int ipl) {
    return 0;  /* No interrupt levels in user space */
}

int splimp(void)
{
	// FIXME
	return 5;
}

void splx(int x)
{
	// FIXME
}

int subyte(void *base, int byte)
{
	return 0;
}

int suibyte(void *base, int byte)
{
	return 0;
}

void microtime(tvp)
	register struct timeval *tvp;
{
	gettimeofday(tvp, NULL);
}

void init_time(void)
{
    struct timeval local_time;
    gettimeofday(&local_time, NULL);
    time_update = local_time.tv_sec;
}

void tick_update(void)
{
    my_time.tv_usec += tick;
    if (my_time.tv_usec >= 1000000) {
        my_time.tv_usec -= 1000000;
        my_time.tv_sec += 1;
        time_update += 1;
    }
}

int getticks(void) { return tick; }

void nanotime(struct timespec *ts) { ts->tv_sec = 0; ts->tv_nsec = 0; }
void getnanotime(struct timespec *tsp) { }
void getmicrouptime(struct timeval *tv) { tv->tv_sec = 0; tv->tv_usec = 0; }


void ovbcopy(const void *src, void *dest, size_t n)
{
	bcopy(src, dest, n);
}

//////////////////////////////////////////////////////////////////////////////
// sys/conf/param.c
//////////////////////////////////////////////////////////////////////////////
#undef curproc
#define HZ 100
int hz = HZ;
int tick = 1000000 / HZ;
typedef struct kauth_cred *kauth_cred_t;
//struct kauth_cred cred_l;
//kauth_cred_t cred0 = NULL;
//struct	ucred ucred0;
extern kauth_cred_t cred0;

//extern struct proc proc0;
struct session session0 = {
	.s_count = 1,
	.s_sid = 0,
};

struct pgrp pgrp0 = {
	.pg_members = LIST_HEAD_INITIALIZER(&pgrp0.pg_members),
	.pg_session = &session0,
};
filedesc_t filedesc0;

struct plimit limit0;
struct pstats pstat0;
struct vmspace vmspace0;
struct sigacts sigacts0;
struct proc proc0 = {
	.p_lwps = LIST_HEAD_INITIALIZER(&proc0.p_lwps),
	.p_sigwaiters = LIST_HEAD_INITIALIZER(&proc0.p_sigwaiters),
	.p_nlwps = 1,
	.p_nrlwps = 1,
	.p_pgrp = &pgrp0,
	.p_comm = "system",
	/*
	 * Set P_NOCLDWAIT so that kernel threads are reparented to init(8)
	 * when they exit.  init(8) can easily wait them out for us.
	 */
	.p_flag = PK_SYSTEM | PK_NOCLDWAIT,
	.p_stat = SACTIVE,
	.p_nice = NZERO,
	//.p_emul = &emul_netbsd,
	//.p_cwdi = &cwdi0,
	.p_limit = &limit0,
	.p_fd = &filedesc0,
	.p_vmspace = &vmspace0,
	.p_stats = &pstat0,
	.p_sigacts = &sigacts0,
#ifdef PROC0_MD_INITIALIZERS
	PROC0_MD_INITIALIZERS
#endif
};

struct proclist allproc;

//extern struct lwp dummy_lwp;
struct lwp lwp0 = {
	.l_lid = 0,
	.l_proc = &proc0,
        .l_cpu = &cpu0,
};


lwp_t *gl_lwp;
struct proc dummy_proc = {0};
extern struct proc *curproc;

__attribute__((constructor)) void init_dummy_lwp() {
    gl_lwp = (struct lwp_t *)&lwp0;
}

static inline lwp_t * __attribute__ ((const)) stub_curlwp(void) { return &lwp0; }
/////////////////////////////////////////////////////////////////////////////
// sys/i386/i386/machdep.c
//////////////////////////////////////////////////////////////////////////////
int cpu_intr_p(void) {
    return 0;  /* Not in interrupt context */
}

//////////////////////////////////////////////////////////////////////////////
// sys/i386/i386/trap.c
//////////////////////////////////////////////////////////////////////////////
int
copyout(const void *from, void *to, size_t len)
{
	bcopy (from, to, len);
	return 0;
}

int copyin(const void* from, void* to, size_t len)
{
	bcopy (from, to, len);
	return 0;
}

//////////////////////////////////////////////////////////////////////////////
// sys/kern/kern_clock.c
//////////////////////////////////////////////////////////////////////////////
/*
 * timeout --
 *	Execute a function after a specified length of time.
 *
 * untimeout --
 *	Cancel previous timeout function call.
 *
 *	See AT&T BCI Driver Reference Manual for specification.  This
 *	implementation differs from that one in that no identification
 *	value is returned from timeout, rather, the original arguments
 *	to timeout are used to identify entries for untimeout.
 */

void
timeout(ftn, arg, ticks)
	void (*ftn) __P((void *));
	void *arg;
	register int ticks;
{
	// FIXME
}

//////////////////////////////////////////////////////////////////////////////
// sys/kern/kern_malloc.c
//////////////////////////////////////////////////////////////////////////////
#include "u_mem.h"

/*
 * Allocate a block of memory
 */
void *
xmalloc(size, type, flags)
	unsigned long size;
	int type, flags;
{
	// mbuf requires 128-byte alignment
    if (size > 8 && (size & (size-1)) == 0) {
        void *ptr = memalign(size, size);
        memset(ptr, 0, size);
        return ptr;
    } else {
        void *ptr = malloc(size);
        memset(ptr, 0, size);
        return ptr;
    }
}

/*
 * Free a block of memory allocated by malloc.
 */
void
xfree(addr, type)
	void *addr;
	int type;
{
	return free(addr);
}

void *kern_malloc(unsigned long reqsize, int flags)
{
    void *ptr = malloc(reqsize);
    memset(ptr, 0, reqsize);
    return ptr;
    //return calloc(reqsize, sizeof(char));
}
void kern_free(void *addr) { free(addr); }

//////////////////////////////////////////////////////////////////////////////
// sys/kern/kern_prot.c
//////////////////////////////////////////////////////////////////////////////
/*
 * Test whether the specified credentials imply "super-user"
 * privilege; if so, and we have accounting info, set the flag
 * indicating use of super-powers.
 * Returns 0 or error.
 */
#if 0
int
suser(cred, acflag)
	struct ucred *cred;
	u_short *acflag;
{
	if (cred->cr_uid == 0) {
		if (acflag)
			*acflag |= ASU;
		return (0);
	}
	return (EPERM);
}
#endif
//////////////////////////////////////////////////////////////////////////////
// sys/kern/kern_synch.c
//////////////////////////////////////////////////////////////////////////////
/*
 * General sleep call.  Suspends the current process until a wakeup is
 * performed on the specified identifier.  The process will then be made
 * runnable with the specified priority.  Sleeps at most timo/hz seconds
 * (0 means no timeout).  If pri includes PCATCH flag, signals are checked
 * before and after sleeping, else signals are not checked.  Returns 0 if
 * awakened, EWOULDBLOCK if the timeout expires.  If PCATCH is set and a
 * signal needs to be delivered, ERESTART is returned if the current system
 * call should be restarted if possible, and EINTR is returned if the system
 * call should be interrupted by the signal (return EINTR).
 */
int
tsleep(ident, priority, wmesg, timo)
	wchan_t ident;
	pri_t priority;
        int timo;
	const char *wmesg;
{
	printf("tsleep\n");
	exit(1);
	return 0;
}

/*
 * Make all processes sleeping on the specified identifier runnable.
 */
void
wakeup(ident)
	wchan_t ident;
{
	// FIXME
}

#if 0
//////////////////////////////////////////////////////////////////////////////
// sys/kern/kern_sysctl.c
//////////////////////////////////////////////////////////////////////////////
/*
 * Validate parameters and get old / set new parameters
 * for an integer-valued sysctl function.
 */
int
sysctl_int(oldp, oldlenp, newp, newlen, valp)
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	int *valp;
{
	int error = 0;

	if (oldp && *oldlenp < sizeof(int))
		return (ENOMEM);
	if (newp && newlen != sizeof(int))
		return (EINVAL);
	*oldlenp = sizeof(int);
	if (oldp)
		error = copyout(valp, oldp, sizeof(int));
	if (error == 0 && newp)
		error = copyin(newp, valp, sizeof(int));
	return (error);
}

void
sysctl_unlock(void)
{
}
void
sysctl_relock(void)
{
}
#endif


//////////////////////////////////////////////////////////////////////////////
// sys/kern/subr_prf.c
//////////////////////////////////////////////////////////////////////////////
void panic(const char *fmt, ...)
{
    printf("panic: ");
    // FIXME
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");

     exit(1);
}

/*
 * Log writes to the log buffer, and guarantees not to sleep (so can be
 * called by interrupt routines).  If there is no process reading the
 * log yet, it writes to the console also.
 */
void log(int level, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

//////////////////////////////////////////////////////////////////////////////
// sys/kern/subr_proc.c
//////////////////////////////////////////////////////////////////////////////
/*
 * Other process lists
 */
#if 0
struct pidhashhead *pidhashtbl;
u_long pidhash;

/*
 * Locate a process by number
 */
struct proc *
pfind(pid)
	register pid_t pid;
{
	register struct proc *p;

	for (p = PIDHASH(pid)->lh_first; p != 0; p = p->p_hash.le_next)
		if (p->p_pid == pid)
			return (p);
	return (NULL);
}
#endif
//////////////////////////////////////////////////////////////////////////////
// sys/kern/sys_generic.c
//////////////////////////////////////////////////////////////////////////////
/*
 * Do a wakeup when a selectable event occurs.
 */
void
selwakeup(sip)
	register struct selinfo *sip;
{
}

//////////////////////////////////////////////////////////////////////////////
// sys/kern/uipc_syscalls.c
//////////////////////////////////////////////////////////////////////////////
int
sockargs(mp, buf, buflen, seg, type)
	struct mbuf **mp;
	const void *buf;
	size_t buflen;
        enum uio_seg seg;
        int type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
#ifdef COMPAT_OLDSOCK
		if (type == MT_SONAME && (u_int)buflen <= 112)
			buflen = MLEN;		/* unix domain compat. hack */
		else
#endif
		return (EINVAL);
	}
	m = m_get(M_WAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	m->m_len = buflen;
	error = copyin(buf, mtod(m, void *), (u_int)buflen);
	if (error) {
		(void) m_free(m);
		return (error);
	}
	*mp = m;
	if (type == MT_SONAME) {
		sa = mtod(m, struct sockaddr *);

#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
		if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
			sa->sa_family = sa->sa_len;
#endif
		sa->sa_len = buflen;
	}
	return (0);
}


/*
 * sys/kern/kern_proc.c *
 */

bool
get_expose_address(struct proc *p)
{
    return true;
}



struct pgrp *pgrp_find(pid_t pgid) { return NULL; }

/*
 * sys/kern/subr_percpu.c
 */

struct percpu_dummy {
	unsigned		pc_offset;
	size_t			pc_size;
	percpu_callback_t	pc_ctor;
	percpu_callback_t	pc_dtor;
	void			*pc_cookie;
        void                    *aa;
        void                    *bb;
};

struct percpu {
    struct percpu_dummy pc_items[1];	
};
typedef struct percpu percpu_t;

percpu_t *cur_percpu;

#if 1
percpu_t *
percpu_alloc(size_t size)
{

    //cur_percpu = (percpu_t *)calloc(1, size * 2000);
    cur_percpu = (percpu_t *)calloc(16000, sizeof(struct percpu));
    return cur_percpu;
}

void percpu_free(percpu_t *pc, size_t size)
{
    free(pc);
}
static percpu_t *new_percpu;
void *
percpu_getref(percpu_t *pc)
{
    //return cur_percpu;
    return pc;
}
void
percpu_putref(percpu_t *pc)
{

}

void percpu_foreach(percpu_t *pc, percpu_callback_t cb, void *arg) {
    cb((void *)&pc->pc_items[0], arg, &cpu0);
}

void percpu_traverse_enter(void) {}
void percpu_traverse_exit(void) {}

percpu_t *percpu_create(size_t size, percpu_callback_t ctor,
        percpu_callback_t dtor, void *cookie)
{
    new_percpu = (percpu_t *)calloc(16000, sizeof(struct percpu));
    return &new_percpu;
}

void *percpu_getptr_remote(percpu_t *pc, struct cpu_info *ci) {
    //static struct cpu_info *cpu = &cpu0;
    //return &cpu;
    return &pc;
}

void percpu_foreach_xcall(percpu_t *pc, u_int xcflags, 
        percpu_callback_t func,
        void *arg) {
    func(pc, arg, &cpu0);  // 单 CPU 模拟
}


#endif
unsigned int xc_encode_ipl(int ipl) {
    return 0;  // 返回伪造的 IPL
}

uint64_t
xc_unicast(unsigned int flags, xcfunc_t func, void *arg1, void *arg2,
    struct cpu_info *ci)
{
    (*func)(arg1, arg2); // 直接调用函数，忽略 CPU 特定逻辑
}
#if 0
// 模拟 vmem_xcreate
vmem_t *
vmem_xcreate(const char *name, vmem_addr_t base, vmem_size_t size,
    vmem_size_t quantum, vmem_ximport_t *importfn, vmem_release_t *releasefn,
    vmem_t *source, vmem_size_t qcache_max, vm_flag_t flags, int ipl)
{
    printf("vmem_xcreate: allocating %zu bytes for %s\n", size, name);
    return (vmem_t *)malloc(size); // 简单返回 malloc 分配的内存
}
#endif
// 模拟 explicit_memset
void *
explicit_memset(void *ptr, int value, size_t len)
{
    printf("explicit_memset: clearing %zu bytes at %p\n", len, ptr);
    return memset(ptr, value, len); // 使用标准 memset
}


struct cpu_info *cpu_lookup(unsigned int cpuid) {
    return &cpu0;  // 总是返回 cpu0
}

/* multiple cpu */
void xc_barrier(unsigned int flags) {}

/*
 * mutex related
 */
kmutex_t proc_lock;
kmutex_t *mutex_obj_alloc(kmutex_type_t type, int ipl) {
    return NULL;  /* No real mutex needed */
}

void mutex_init(kmutex_t *mtx, kmutex_type_t type, int ipl) {
    /* No-op for stub */
}

void mutex_enter(kmutex_t *mtx) {
    /* No-op */
    //printf("Stub mutex_enter\n");
}
int mutex_tryenter(kmutex_t *mtx) { return 1; }

void mutex_exit(kmutex_t *mtx) {
    /* No-op */
    //printf("Stub mutex_exit\n");
}

void mutex_destroy(kmutex_t *mtx) {}

void mutex_obj_hold(kmutex_t *mtx) {}  /* Always held */
bool mutex_obj_free(kmutex_t *mtx) { return true; }
int mutex_owned(const kmutex_t *mtx) { return 1; }

void mutex_spin_enter(kmutex_t *mtx) {}
void mutex_spin_exit(kmutex_t *mtx) {}

/*
 * rwlock related
 */
#include "sys/rwlock.h"  /* For krwlock_t */

//typedef int krwlock_t;  /* Dummy type */
#define RW_READER 1     /* Stub mode */
#define RW_WRITER 2     /* Stub mode */

void rw_init(krwlock_t *lock) {
    /* No-op for stub */
}

void rw_enter(krwlock_t *lock, const krw_t mode) {
    /* No-op */
    //printf("Stub rw_enter\n");
}
void rw_exit(krwlock_t *lock) {
}

krwlock_t *rw_obj_alloc(void) { return NULL; }
bool rw_obj_free(krwlock_t *lock) { return true; };

int rw_lock_held(krwlock_t *lock) {
    return 1;  /* Always true in stub; assumes lock is "held" */
}

int rw_tryenter(krwlock_t *lock, const krw_t  mode) {
    return 1;  /* Success */
}
int rw_read_held(krwlock_t *lock) {
    return 1;  /* Success */
}
int rw_write_held(krwlock_t *lock) {
    return 1;  /* Success */
}



int rw_tryupgrade(krwlock_t *lock) { return 0; }

void rw_destroy(krwlock_t *lock) {
    /* No-op in stub */
    //printf("Stub rw_destroy\n");
}

/*
 * soft interrupt and wakeup
 */
struct softint_handle_t {
    void *intrh;
    void *arg;
};

static struct softint_handle_t gl_sh[512];
static int handle_index = 0;

void softint_schedule(void *si) {
    /* No-op for now */
    void (*intrh)(void *);
    struct softint_handle_t *sh = (struct softint_handle_t *)si;
    intrh = sh->intrh;
    intrh(sh->arg);
}

static void *dummy_sih = (void *)1;
void *softint_establish(u_int flags, void (*func)(void *), void *arg) {
    //return dummy_sih;  /* No softints in user space */
    if (handle_index >=256) {
        printf("Out of range of softint: %d\n", handle_index);
        exit(1);
    }
    gl_sh[handle_index].intrh = func;
    gl_sh[handle_index].arg = arg;
    void *sih = &gl_sh[handle_index];
    handle_index++;
    return (void *)sih;
}


void softint_schedule_cpu(void *arg, struct cpu_info *ci_tgt)
{
    return softint_schedule(arg);
}
void sleepq_init(void *sq) {}

void sleepq_wake(void *sq) {
    /* No-op */
}
void sleepq_enter(void *sq, struct lwp *l, kmutex_t mtx) {}
void sleepq_enqueue(void *sq, const void *wchan, const char *msg) {}
int sleepq_block(int timo, bool catch) { return 0; }  /* Return success */
void sleepq_unsleep(struct lwp *l) {}
void sleepq_changepri(struct lwp *l, int pri) {}
void sleepq_lendpri(struct lwp *l, int pri) {}


struct wq {
    int ww_off;
    int	ww_proto;
    void *func;
};

static struct wq wq_data[32];
static int wq_index = 0;

int workqueue_create(struct workqueue **wq, const char *name, void (*func)(struct work *, void *), void *arg, pri_t pri, int ipl, int flags) {
    return 0;
}
void workqueue_wait(struct workqueue *wq, struct work *arg) {}
void workqueue_enqueue(struct workqueue *wq, struct work *wk0, struct cpu_info *ci) {}
void workqueue_destroy(struct workqueue *wq) {}
void *wqinput_create(const char *name, void (*func)(struct mbuf *, int, int))
{
    if (wq_index >= 32) {
        printf("wq_index > 32.\n");
        exit(1);
    }
    struct wq *w = &wq_data[wq_index++];
    w->func = func;
    return w;
}
void wqinput_input(struct wqinput *wqi, struct mbuf *m, int off, int proto) {
    struct wq *w = (struct wq *)wqi;
    void (*func)(struct mbuf *, int, int);
    func = w->func;
    func(m, off, proto);
}

/*
 * sys/kern/subr_pool.c
 */
int nullop(void* p) { return 0; }
int ncpu = 1;
struct cpu_info *cpu_info_list = &cpu0;
int cold = 0;
void membar_release(void) {}

/*
 * sys/kern/kern_descrip.c
 */
//LIST_HEAD(, proc) allproc;  /* Match kernel’s expected type */

/*
 * sys/kern/kern_auth.c
 */ 
int kauth_authorize_process(kauth_cred_t cred, kauth_action_t action,
    struct proc *p, void *arg1, void *arg2, void *arg3)
{
    return 0;
}

int kauth_authorize_network(struct kauth_cred * cred, kauth_action_t action, enum kauth_network_req arg1, void *arg2, void *arg3, void *arg4) {
    return 0;  /* Always allow */
}

kauth_listener_t kauth_listen_scope(const char *scope, kauth_scope_callback_t cb, void *arg) { return NULL; }
uid_t kauth_cred_geteuid(kauth_cred_t cred) { return 0; }  /* Root UID */
struct uidinfo *uid_find(uid_t uid) { static struct uidinfo ui = {0}; return &ui; }
gid_t kauth_cred_getegid(kauth_cred_t cred) { return 0; }  /* Root GID */
kauth_cred_t kauth_cred_hold(kauth_cred_t cred) { return cred; }
void kauth_cred_free(kauth_cred_t cred) {}
kauth_cred_t kauth_cred_get(void) { return NULL; }
int kauth_authorize_system(kauth_cred_t cred, kauth_action_t action,
    enum kauth_system_req req, void *arg1, void *arg2, void *arg3)
{
    return 0;
}

/*
 * sys/kern/kern_condvar.c
 */
void
cv_init(kcondvar_t *cv, const char *wmesg)
{
}
void
cv_broadcast(kcondvar_t *cv)
{
}
void
cv_wait(kcondvar_t *cv, kmutex_t *mtx)
{
}
void cv_signal(kcondvar_t *cv) {}  /* No-op for single-threaded */
int cv_wait_sig(kcondvar_t * cv, struct kmutex * mtx) { return 0; }  /* No blocking in single-threaded */
int cv_timedwait(kcondvar_t  *cv, kmutex_t *mtx, int ticks) { return 0; }
int cv_timedwait_sig(kcondvar_t *cv, kmutex_t *mtx, int timo) { return 0; }  /* No-op for single-threaded */
void cv_destroy(kcondvar_t *cv) {}


/*
 * automic related
 */
void atomic_inc_uint(volatile unsigned int *ptr) {
    (*ptr)++;
}
void atomic_dec_uint(volatile unsigned int *ptr) { (*ptr)--; }

unsigned int atomic_dec_uint_nv(volatile unsigned int *ptr) {
    return --(*ptr);  /* Non-atomic for single-threaded */
}

unsigned int atomic_inc_uint_nv(volatile unsigned int *val) { return ++(*val); }
void *atomic_cas_ptr(volatile void *ptr, void *old, void *new) { if (*(void **)ptr == old) { *(void **)ptr = new; return old; } return *(void **)ptr; }

uint32_t atomic_cas_32(volatile uint32_t *ptr, uint32_t oldval, uint32_t newval) {
    uint32_t old = *ptr;
    if (old == oldval) *ptr = newval;
    return old;
}

void membar_producer(void) {
}

void membar_acquire(void) {
    /* No-op in single-threaded user space */
}

/*
 * virtual addr to physical add
 */
struct uvmexp uvmexp = {0};

unsigned long vtophys(vaddr_t vaddr) {
    return (unsigned long)vaddr;  /* No virtual-to-physical in user space */
}
vaddr_t uvm_km_alloc(struct vm_map *map, vsize_t size, vsize_t align, uvm_flag_t flag_t)
{
    void *ptr = malloc(size);
    memset(ptr, 0, size);
    return (vaddr_t)ptr;
}
void uvm_km_free(struct vm_map *map, vaddr_t addr, vsize_t size, uvm_flag_t flags) { free((void *)addr); }
void uvm_unloan(vaddr_t va, int npages) {}
int uvm_loan(struct vm_map *map, vaddr_t vaddr, vsize_t size, void *loan) { return 0; }  /* No loans needed */
unsigned long uvm_vm_page_to_phys(void *page) { return 0; }  /* Dummy physical address */

int proc_uidmatch(kauth_cred_t p1, kauth_cred_t p2) { return 1; }  /* Always match */

struct pmap *const kernel_pmap_ptr = NULL;
struct vm_map *kernel_map = NULL;

void pmap_kenter_pa(vaddr_t va, paddr_t pa, vm_prot_t port, u_int flags) {}
void pmap_kremove(vaddr_t va, vsize_t size) {}
void pmap_update(pmap_t pmap) {}

/* kthread to function */
int kthread_create(int pri, int flags, void *cpu, void (*func)(void *), void *arg, struct lwp **lwp, const char *fmt) {
    func(arg);  /* Call directly, no thread */
    if (lwp) *lwp = NULL;  /* No lwp created */
    return 0;
}

/*
 * socket related
 */
struct socket;

/* Minimal fileops stub for socketops */
int soo_read(struct file *fp, off_t *off, struct uio *uio, kauth_cred_t cred, int flags) { return 0; }
int soo_write(struct file *fp, off_t *off, struct uio *uio, kauth_cred_t cred, int flags) { return 0; }
int soo_ioctl(struct file *fp, u_long cmd, void *data) { return 0; }
int soo_close(struct file *fp) { return 0; }
int soo_noop() { return 0; }

const struct fileops socketops = {
    .fo_read = soo_read,
    .fo_write = soo_write,
    .fo_ioctl = soo_ioctl,
    .fo_fcntl = soo_noop,
    .fo_poll = soo_noop,
    .fo_stat = soo_noop,
    .fo_close = soo_close,
#ifndef __NetBSD__
    /* NetBSD-specific fields might differ; adjust if needed */
    .fo_restart = soo_noop,
    .fo_kqfilter = soo_noop,
#endif
};

int chgsbsize(struct uidinfo *uip, u_long *buf, u_long to, rlim_t max) {
    *buf = to; 
    return 1; 
}
int accept_filt_clear(struct socket *so) {}
int accept_filt_setopt(struct socket *so, const struct sockopt *optval) { return 0; }
int accept_filt_getopt(struct socket *so, struct sockopt *sopt) { return 0; }

/* Stub function for ifioctl pointer */
static int ifioctl_stub(struct socket *so, u_long cmd, void *data, struct lwp *l) { return 0; }

/* Define the ifioctl pointer */
int (*ifioctl)(struct socket *, u_long, void *, struct lwp *) = ifioctl_stub;

uint8_t sockaddr_dl_measure(uint8_t namelen, uint8_t addrlen)
{
    return offsetof(struct sockaddr_dl, sdl_data[namelen + addrlen]);
    //return sizeof(struct sockaddr_dl);
}


struct sockaddr_dl *sockaddr_dl_setaddr(struct sockaddr_dl *sdl, socklen_t sdllen,
        const void *addr, uint8_t addrlen)
{

    socklen_t len;
    len = sockaddr_dl_measure(sdl->sdl_nlen, addrlen);
    memcpy(&sdl->sdl_data[sdl->sdl_nlen], addr, addrlen);
    sdl->sdl_alen = addrlen;
    sdl->sdl_len = len;
    return sdl;
}
struct sockaddr_dl *sockaddr_dl_init(struct sockaddr_dl *sdl, socklen_t socklen, uint16_t ifindex,
        uint8_t type, const void *name, uint8_t namelen, const void *addr,
        uint8_t addrlen)
{
    socklen_t len;
    sdl->sdl_family = AF_LINK;
    sdl->sdl_slen = 0;

    len = sockaddr_dl_measure(namelen, addrlen);
    sdl->sdl_len = len;
    sdl->sdl_index = ifindex;
    sdl->sdl_type = type;
    memset(&sdl->sdl_data[0], 0, namelen + addrlen);
    if (name != NULL) {
        memcpy(&sdl->sdl_data[0], name, namelen);
        sdl->sdl_nlen = namelen;
    } else
        sdl->sdl_nlen = 0;
    if (addr != NULL) {
        memcpy(&sdl->sdl_data[sdl->sdl_nlen], addr, addrlen);
        sdl->sdl_alen = addrlen;
    } else
        sdl->sdl_alen = 0;
    return sdl;
}

/*
 * uio related
 */
int uiomove(void *buf, size_t len, struct uio *uio) {
    struct iovec *iov;
    size_t cnt;
    char *cp = buf;
    int error = 0;

    while (len > 0 && uio->uio_resid > 0) {
        iov = uio->uio_iov;
        cnt = iov->iov_len;
        if (cnt == 0) {
            uio->uio_iov++;
            uio->uio_iovcnt--;
            continue;
        }
        if (cnt > len)
            cnt = len;
        if (cnt > uio->uio_resid)
            cnt = uio->uio_resid;

        if (uio->uio_rw == UIO_READ) {
            memcpy((char *)iov->iov_base + uio->uio_offset, cp, cnt);
        } else {
            memcpy(cp, (char *)iov->iov_base + uio->uio_offset, cnt);
        }

        cp += cnt;
        len -= cnt;
        iov->iov_len -= cnt;
        uio->uio_resid -= cnt;
        uio->uio_offset += cnt;
    }

    return error;
}

/* module hook stub */
void *uipc_socket_50_setopt1_hook = NULL;
void *uipc_socket_50_getopt1_hook = NULL;
void *uipc_socket_50_sbts_hook = NULL;
void *uipc_syscalls_40_hook = NULL;
void *uipc_syscalls_50_hook = NULL;
void *if_cvtcmd_43_hook = NULL;
void *ifmedia_80_pre_hook = NULL;
void *if_ifioctl_43_hook = NULL;
void *ifmedia_80_post_hook = NULL;
void *rtsock_iflist_70_hook = NULL;
void *rtsock_iflist_14_hook = NULL;
void *rtsock_iflist_50_hook = NULL;
void *rtsock_oifmsg_14_hook = NULL;
void *rtsock_oifmsg_50_hook = NULL;
void *rtsock_newaddr_70_hook = NULL;
void *net_inet6_nd_90_hook = NULL;

bool module_hook_tryenter(bool *b, struct localcount *hook) { return 0; }  /* No hook available */
void module_hook_exit(struct localcount *hook) {}
void module_hook_set(bool *hooked, struct localcount *lc) {}
void module_hook_unset(bool *hooked, struct localcount *lc) {}
int enosys(void) { return ENOSYS; }

/*
 *  avoid kqueue notify, etc
 */
void selnotify(struct selinfo *sip, int events, long knhint) {}
void selrecord(lwp_t *selector, struct selinfo *sip) {}
bool selremove_knote(struct selinfo *sip, struct knote *kn) { return false; }
void selinit(struct selinfo *sip) {}
void seldestroy(struct selinfo *sip) {}
void selrecord_knote(struct selinfo *sip, struct knote *kn) {}
void knote_set_eof(struct knote *kn, uint32_t flags) {}
int seltrue(dev_t dev, int events, lwp_t *l) { return 1; }
int seltrue_kqfilter(struct file *fp, void *kn) { return 1; }

/*
 * pint and bpf filter
 */
const char hexdigits[] = "0123456789abcdef";
const int schedppq = 1;
void psref_target_init(struct psref_target *target, struct psref_class *class) {}
struct psref_class *psref_class_create(const char *name, int flags) { return NULL; }
void psref_acquire(struct psref *psref, const struct psref_target *target,
        struct psref_class *class) {}
void psref_release(struct psref *psref, const struct psref_target *target,
        struct psref_class *class) {}
void psref_target_destroy(struct psref_target *target, struct psref_class *class) {}
bool psref_held(const struct psref_target *psref, struct psref_class *class) { return true; }
void psref_copy(struct psref *pto, const struct psref *pfrom,
    struct psref_class *class) {}
void psref_class_destroy(struct psref_class *class) {}

pfil_head_t *pfil_head_create(int type, void *arg) { return NULL; }
void pfil_head_destroy(pfil_head_t *ph) {}
void pfil_run_ifhooks(pfil_head_t *ph, u_long cmd, struct ifnet *ifp) {}
int pfil_add_hook(pfil_func_t func, void *arg, int flags, pfil_head_t *ph) { return 0; }
int pfil_remove_hook(pfil_func_t func, void *arg, int flags, pfil_head_t *ph) { return 0; }
int pfil_run_hooks(pfil_head_t *ph, struct mbuf **mp, ifnet_t *ifp, int dir) { return 0; }
void pfil_run_addrhooks(pfil_head_t *ph, u_long cmd, struct ifaddr *ifa) {}

/*
 * link layer
 */

int carp_proto_input(struct mbuf *m, int *offp, int proto) { return 0; }
int carp6_proto_input(struct mbuf *m, int *offp, int proto) { return 0; }
void carp_init(void) {}

#define	IF_STATS_SIZE	(sizeof(uint64_t) * IF_NSTATS)
void if_stats_init(ifnet_t * const ifp) {
    ifp->if_stats = percpu_alloc(IF_STATS_SIZE);
}
void carp_ifdetach(void *ifp) {}
void if_stats_to_if_data(struct ifnet *ifp, struct if_data *ifd, bool zero_stats) {}
void if_stats_fini(ifnet_t * const ifp) {}
int module_autoload(const char *name, const char *class) { return ENOENT; }
void carp_carpdev_state(void *ifp) {}
int carp_ourether(void *ifp, struct mbuf **mp, const uint8_t *dest) { return 0; }
void carp_input(struct ifnet *ifp, struct mbuf **mp) {};
int carp_iamatch(struct ifnet *ifp, const struct in_addr *addr) { return 0; }
int carp_iamatch6(struct ifnet *ifp, const struct in_addr *addr) { return 0; }

/* no soft interrupts */
void softint_disestablish(void *si) {}

/* bstp related */
const uint8_t *bstp_etheraddr = NULL;
void bstp_initialization(struct ifnet *ifp) {}
void bstp_stop(struct ifnet *ifp) {}
int bstp_input(struct ifnet *ifp, struct mbuf **mp) { return 0; };


/* ether related */
int ether_sw_offload_tx(struct ifnet *ifp, struct mbuf *m) { return 0; }

/* kern/subr_entropy.c */
uint32_t entropy_epoch(void) { return 0; }
void rnd_add_data(void *ctx, const void *buf, size_t len, uint32_t entropy) {}

/*sys/net/agr/if_agr.c */
void agr_input(struct ifnet *ifp, struct mbuf **mp) {}

/* sys/net/if_pppoe.c, ieee8023ad_lacp.c */
void pppoedisc_input(struct ifnet *ifp, struct mbuf **mp) {}
void pppoe_input(struct ifnet *ifp, struct mbuf **mp) {}
int ieee8023ad_lacp_input(struct ifnet *ifp, struct mbuf **mp) { return 0; }
int ieee8023ad_marker_input(struct ifnet *ifp, struct mbuf **mp) { return 0; }

struct pktqueue {
    void *pq_sih;
    void *data;
};

typedef struct pktqueue pktqueue_t;
/* sys/net/if_pktq.c */
uint32_t pktq_rps_hash(const pktq_rps_hash_func_t *funcp, const struct mbuf *m) { return 0; }
void pktq_ifdetach(void) {}
bool pktq_enqueue(pktqueue_t *pq, struct mbuf *m, const u_int hash __unused)
{
    void (*intrh)(void *);
    struct softint_handle_t *sh = (struct softint_handle_t *)(pq->pq_sih);
    intrh = sh->intrh;
    pq->data = m;
    intrh(sh->arg);
     
    return true;
}
int sysctl_pktq_rps_hash_handler(SYSCTLFN_ARGS) { return 0; }
static uint32_t stub_pktq_rps_hash_default(struct mbuf *m) { return 0; }
const pktq_rps_hash_func_t pktq_rps_hash_default = stub_pktq_rps_hash_default;
pktqueue_t *pktq_create(size_t maxlen, void (*intrh)(void *), void *sc)
{
    struct pktqueue *pq = (struct pktqueue *)calloc(1, sizeof(*pq));
    void *sih = softint_establish(0, intrh, NULL);
    pq->pq_sih = sih;
    pq->data = NULL;
    return pq;
}
struct mbuf *pktq_dequeue(pktqueue_t *pq) {
    struct mbuf *m = NULL;
    if (pq->data) {
        m = (struct mbuf *)pq->data;
        pq->data = NULL;
    }
    return m;
};
void
pktq_sysctl_setup(pktqueue_t * const pq, struct sysctllog ** const clog,
		  const struct sysctlnode * const parent_node, const int qid)
{
}

/* sys/kern/subr_prf.c */
void aprint_error(const char *fmt, ...) {}

/* sys/kern/kern_stub.c */
int
enxio(void)
{
	return (ENXIO);
}
void kpreempt_disable(void) {}
void kpreempt_enable(void) {}
bool kpreempt_disabled(void) { return true; }


/* sys/net/if_media.c */
int ifmedia_ioctl(struct ifnet *ifp, struct ifreq *ifr, struct ifmedia *ifm, u_long cmd) { return 0; }

/* sys/lib/libkern/kern_assert.c */
void kern_assert(const char *fmt, ...) {}

/* sys/net/raw_cb.c */
void raw_attach(struct socket *so, int proto) {}
void raw_detach(struct socket *so) {}
void raw_disconnect(struct socket *so) {}

/* sys/net/rtsock_shared */
vec_sctp_add_ip_address = NULL;
vec_sctp_delete_ip_address = NULL;

/* sys/net/net_stats.c */
int netstat_sysctl(percpu_t *stat, u_int ncounters, SYSCTLFN_ARGS) { return 0; }

size_t coherency_unit = 64;

int _init_once(once_t *o, int (*fn)(void))
{
    if (o->o_refcnt++ == 0) {
        o->o_error = fn();
    }
    return 0;
}

/* ppsrate */
int
ppsratecheck(lasttime, curpps, maxpps)
	struct timeval *lasttime;
	int *curpps;
	int maxpps;	/* maximum pps allowed */
{
    return 1;
}

/* sys/kern/subrthmap.c */
thmap_t *thmap_create(uintptr_t baseptr, const thmap_ops_t *ops, unsigned flags) { return NULL; }
void *thmap_get(thmap_t *thmap, const void *key, size_t len) { return NULL; }
void *thmap_put(thmap_t *thmap, const void *key, size_t len, void *val) { return NULL; }
void *thmap_del(thmap_t *thmap, const void *key, size_t len) { return NULL; }
void *thmap_stage_gc(thmap_t *thmap) { return NULL; }
void thmap_gc(thmap_t *thmap, void *ref) {}

/* atomic related */
unsigned int atomic_cas_uint(volatile unsigned int *ptr, unsigned int old, unsigned int new) { if (*ptr == old) { *ptr = new; return old; } return *ptr; }
void atomic_and_uint(volatile unsigned int *ptr, unsigned int val) { *ptr &= val; }
void atomic_or_uint(volatile unsigned int *ptr, unsigned int val) { *ptr |= val; }


void *kern_cprng = NULL;
void *cprng_strong = NULL;

/* ipv6 related */
//int sin6_print(char *buf, size_t len, const void *v) { return 0; }

/* sys/crpto/cprng_fast/cprng_fastp.c */
uint32_t cprng_fast32(void) {
    //return 0;
    return (uint32_t)rand();
}
uint32_t cprng_fast(void) {
    //return 0;
    return (uint32_t)rand();
}
uint32_t cprng_strong32(void) {
    //return 0;
    return (uint32_t)rand();
}


/* crypto */
void MD5Init(void *ctx) {}
void MD5Update(void *ctx, const void *data, size_t len) {}
void MD5Final(unsigned char *digest, void *ctx) {}

/* sys/kern/kern_ktrace.c */
int ktrace_on = 0;
void ktr_mibio(int a, int b, int c) {}
void ktr_mib(int a, int b) {}

/* sys/kern/subr_asan.c */
int
kcopy(const void *src, void *dst, size_t len)
{
	memcpy(dst, src, len);
#ifdef DEBUG
	if (memcmp(dst, src, len) != 0)
		panic("kcopy not finished correctly\n");
#endif
	return 0;
}

int
copyinstr(const void *uaddr, void *kaddr, size_t len, size_t *done)
{
	len = uimin(strnlen(uaddr, len), len) + 1;
	strncpy(kaddr, uaddr, len);
	if (done)
		*done = len;
	return 0;
}

/* sysctl related */
//void sysctl_basenode_init(void) {}
/* ?? */
void blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {}

/* sys/kern/kern_event.c */
void knote_fdclose(int fd) {}

/* sys/kern/kern_synch.c */
int kpause(const char *reason, bool intr, int ticks, kmutex_t *mtx) { return 0; }
uintptr_t syncobj_noowner(wchan_t wchan) { return 0; }

u_int maxfiles = 1024;

/* sys/kern/subr_prf.c */
void tablefull(const char *tab, const char *hint) {}

struct proc *proc_find(pid_t pid) { return NULL; }
int pgid_in_session(struct proc *p, pid_t pgid) { return 0; }

/* sys/kern/kern_sig.c */
void kpsignal(struct proc *p, ksiginfo_t *ksi, void *data) {}
void kpgsignal(struct pgrp *pg, ksiginfo_t *ksi, void *data, int checkctty) {}

int (*devenodev)(struct file *, void *) = NULL;
int (*ttyvenodev)(struct file *, void *) = NULL;

/* sys/kern/subr_devsw.c */
int nommap(struct file *fp, void *addr, size_t len) { return ENODEV; }

/* sys/kern/subr_evcnt.c */
void evcnt_attach_dynamic(struct evcnt *ev, int type, const struct evcnt *parent,
    const char *group, const char *name) {}

/* sys/kern/kern_rate.c */
int ratecheck(struct timeval *lasttime, const struct timeval *mininterval) { return 1; }

bool mp_online = true;

/* sys/kern/subr_xcall.c */
uint64_t xc_broadcast(unsigned int flags, xcfunc_t func, void *arg1, void *arg2) { return 1; }
void xc_wait(uint64_t where) {};


long lwp_pctr(void) { return 0; }

kmutex_t exec_lock;


/* sysctl base related */
const char ostype[] = "NetBSD";
const char osrelease[] = "10.0";
const char version[] = "NetBSD 10.0 (USERSPACE)";
char machine[] = "x86_64";
char machine_arch[] = "x86_64";
const char *cpu_getmodel(void) {
    return "Unknown CPU";
}
int ncpuonline = 1;

/*device call*/
devhandle_t dummy_devhandle;
int		device_call_generic(device_t dev, devhandle_t handle,
		    const struct device_call_generic *dcg) {return 0;}
devhandle_t	device_handle(device_t dev) { return dummy_devhandle;}

ssize_t
device_getprop_data(device_t dev, const char *prop, void *buf, size_t buflen)
{ return 0; }
