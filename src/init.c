#include "stub.h"
#include "init.h"

typedef struct kauth_cred *kauth_cred_t;
kauth_cred_t cred0 = NULL;
static struct proc dummy_proc = {0};
extern volatile struct	timeval my_time;
extern struct cpu_info cpu0;

struct lwp dummy_lwp;
extern lwp_t *gl_lwp;


void updatetime()
{
  microtime((struct timeval *)&my_time);
}

void setipaddr(const char* name, uint ip)
{
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

  sofree(so);  // FIXME: this doesn't free memory
}

void cpu_startup()
{
}

void netbsd_init()
{
    curproc->p_cred = &cred0;
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

extern int tcp_msl_local;

void sysctl_tun(char *name, int val)
{
    if (strcmp(name, "tcp_msl_local") == 0) {
        tcp_msl_local = val;
    }
}

