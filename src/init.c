#include "stub.h"
#include "init.h"

//struct	pcred cred0;
//struct	ucred ucred0;
typedef struct kauth_cred *kauth_cred_t;
//struct kauth_cred cred_l;
kauth_cred_t cred0 = NULL;
static struct proc dummy_proc = {0};
//struct proc *curproc;
extern volatile struct	timeval time;
extern struct cpu_info cpu0;
//extern struct proc *curproc;

struct lwp dummy_lwp;
extern lwp_t *gl_lwp;

#if 0
void cpu_init()
{

#undef malloc
extern void *malloc (size_t __size);

    curproc = malloc(sizeof(*curproc));
    *curproc = dummy_proc;
}
#endif

void updatetime()
{
  microtime((struct timeval *)&time);
}

void setipaddr(const char* name, uint ip)
{
  //int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct ifreq req;
  bzero(&req, sizeof req);
  strcpy(req.ifr_name, name);
  struct sockaddr_in loaddr;
  bzero(&loaddr, sizeof loaddr);
  loaddr.sin_len = sizeof loaddr;
  loaddr.sin_family = AF_INET;
  loaddr.sin_addr.s_addr = htonl(ip);
  bcopy(&loaddr, &req.ifr_addr, sizeof loaddr);
  struct socket* so = NULL;
  socreate(AF_INET, &so, SOCK_DGRAM, 0, gl_lwp, NULL);
  //ifioctl(so, SIOCSIFADDR, (void *)&req, curproc);

  sofree(so);  // FIXME: this doesn't free memory
}

void cpu_startup()
{
#if 0
        /*
         * Finally, allocate mbuf pool.  Since mclrefcnt is an off-size
         * we use the more space efficient malloc in place of kmem_alloc.
         */
        mclrefcnt = (char *)malloc(NMBCLUSTERS+CLBYTES/MCLBYTES,
                                   M_MBUF, M_NOWAIT);
        bzero(mclrefcnt, NMBCLUSTERS+CLBYTES/MCLBYTES);
/*
        mb_map = kmem_suballoc(kernel_map, (vm_offset_t)&mbutl, &maxaddr,
                               VM_MBUF_SIZE, FALSE);
*/
#endif
}

void netbsd_init()
{
    //cpu_init();
    printf("bbbb\n");
    curproc->p_cred = &cred0;
    //curproc->p_ucred = &ucred0;
    curproc->p_cred = &cred0;
    
    pool_subsystem_init();
    
    sysctl_init();
    ifinit1(); 
    lltableinit();
    
    bpf_setops();
    mbinit();
    soinit();
    cpu_startup();
    callout_startup();
    callout_init_cpu(&cpu0);
    pool_cache_cpu_init(&cpu0);
    domaininit(true);
    //int s = splimp();
    ifinit();
    //splx(s);

    setipaddr("lo0", 0x7f000001);
    updatetime();
}
