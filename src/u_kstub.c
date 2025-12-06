#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <sys/timevar.h>
#include <sys/timearith.h>

unsigned int atomic_swap_uint(volatile unsigned int *ptr, unsigned int new) {
    unsigned int old = *ptr;
    *ptr = new;
    return old;
}

struct dkwedge_info * dkwedge_find_by_wname(const char *wname) { return NULL; }
const char * device_xname(device_t dv) { return "dummy"; }
dev_t devsw_name2blk(const char *name, char *path, size_t pathlen) { return 0; }
devclass_t device_class(device_t dv) { return 0; }
int device_unit(device_t dv) { return 0; }
bool device_is_a(device_t dv, const char *name) { return false; }
device_t device_find_by_xname(const char *xname) { return NULL; }
void kern_reboot(int howto, char *bootstr) {}
void deviter_init(deviter_t *di, deviter_flags_t dc) {}
device_t deviter_first(deviter_t *di, deviter_flags_t dc) { return NULL; }
device_t deviter_next(deviter_t *di) { return NULL; }
void deviter_release(deviter_t *di) {}
void dkwedge_print_wnames(void) {}
int boothowto = 0;
dev_t dumpdev = 0;
dev_t devsw_blk2chr(dev_t blkdev) { return 0; }
void aprint_normal(const char *fmt, ...) {}
const char * dumpspec = NULL;
const char * devsw_blk2name(dev_t blkdev) { return "dummy"; }
dev_t rootdev = 0;
const char * rootspec = NULL;
struct vfsops * vfs_getopsbyname(const char *name) { return NULL; }
const char *rootfstype = "ffs";
void vfs_delref(struct vfsops *vfsops) {}
void cngetsn(char *cp, size_t size) {}
struct vfs_list_head vfs_list;
device_t root_device = NULL;
int bdev_open(dev_t dev, int flags, int devtype, struct lwp *l) { return 0; }
void tc_setclock(struct timeval *tv) {}
void resettodr(void) {}
void itimer_transition(const struct itimerspec *restrict its, const struct timespec *restrict now,
    struct timespec *restrict old, int *restrict which) {}
void getnanouptime(struct timespec *ts) {}
int tshzto(const struct timespec *ts) { return 0; }
int tshztoup(const struct timespec *ts) { return 0; }
int clock_gettime1(clockid_t clk, struct timespec *ts) { return 0; }
uint64_t tc_getfrequency(void) { return 0; }
int ts2timo(clockid_t id, int flags, struct timespec *ts, int *timo, struct timespec *abs) { return 0; }
int tstohz(const struct timespec *ts) { return 0; }
void * timecounter_lock = NULL;
long time_adjtime = 0;
int itimespecfix(struct timespec *ts) { return 0; }
bool timespecaddok(const struct timespec *ts1, const struct timespec *ts2) { return true; }
int itimerfix(struct timeval *tv) { return 0; }
struct vnode * opendisk(device_t dv) { return NULL; }
int VOP_UNLOCK(struct vnode *vp) { return 0; }
int VOP_IOCTL(struct vnode *vp, u_long command, void *data, int fflag, kauth_cred_t cred) { return 0; }
int vn_lock(struct vnode *vp, int flags) { return 0; }
int VOP_CLOSE(struct vnode *vp, int fflag, kauth_cred_t cred) { return 0; }
void vput(struct vnode *vp) {}
