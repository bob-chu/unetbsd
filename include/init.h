#ifndef __INIT__
#define __INIT__
void netbsd_init();
void user_hardclock();
/* tcp_syn_cache_size: 1..1048576 buckets; set before netbsd_init(). */
void sysctl_tun(char *name, int val);
void u_stack_tick(void);

#endif

