#include "stub.h"
#include "init.h"

typedef struct kauth_cred *kauth_cred_t;
kauth_cred_t cred0 = NULL;
static struct proc dummy_proc = {0};
extern volatile struct	timeval my_time;
extern struct cpu_info cpu0;

struct lwp dummy_lwp;
extern lwp_t *gl_lwp;
extern struct ifnet *lo0ifp;

static int
loop_create(int unit)
{
    struct ifnet *ifp;

    ifp = if_alloc(IFT_LOOP);

    if_initname(ifp, "lo0", unit);

    ifp->if_mtu = (32768 + MHLEN + MLEN);
    ifp->if_flags = IFF_LOOPBACK | IFF_MULTICAST;
#ifdef NET_MPSAFE
    ifp->if_extflags = IFEF_MPSAFE;
#endif
    //ifp->if_ioctl = loioctl;
    //ifp->if_output = looutput;
    ifp->if_type = IFT_LOOP;
    ifp->if_hdrlen = 0;
    ifp->if_addrlen = 0;
    ifp->if_dlt = DLT_NULL;
    IFQ_SET_READY(&ifp->if_snd);
    if (unit == 0)
        lo0ifp = ifp;
    if_initialize(ifp);
    ifp->if_link_state = LINK_STATE_UP;
    if_alloc_sadl(ifp);
    bpf_attach(ifp, DLT_NULL, sizeof(u_int));
    ifp->if_flags |= IFF_RUNNING;
    if_register(ifp);

    return (0);
}


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
  int error = socreate(AF_INET, &so, SOCK_DGRAM, 0, gl_lwp, NULL);
  if (error != 0) {
      printf("Failed to create socket for IP address setup: error %d\n", error);
      return;
  }

  error = ifioctl(so, SIOCSIFADDR, &req, gl_lwp);
  if (error != 0) {
      printf("Failed to set IP address for %s: error %d\n", name, error);
  }

  sofree(so);
}

void cpu_startup()
{
}

#include "u_softint.h"
#include "u_fd.h"

static int g_shutdown = 0;


void netbsd_init()
{
    fd_table_init();
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
    loop_create(0);
    loopinit();
    setipaddr("lo0", 0x7f000001);
    updatetime();
    softint_levels_init();
}


extern int tcp_msl_local;

void sysctl_tun(char *name, int val)
{
    if (strcmp(name, "tcp_msl_local") == 0) {
        tcp_msl_local = val;
    }
}

