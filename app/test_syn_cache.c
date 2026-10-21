#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "init.h"

extern int syn_cache_set_size(int);

int main(void)
{
    assert(syn_cache_set_size(0) == EINVAL);
    assert(syn_cache_set_size(-1) == EINVAL);
    assert(syn_cache_set_size(1048577) == EINVAL);
    assert(syn_cache_set_size(1048576) == 0);
    assert(syn_cache_set_size(1) == 0);
    sysctl_tun("tcp_syn_cache_size", 4099);
    netbsd_init();
    assert(syn_cache_set_size(8191) == EBUSY);
    sysctl_tun("tcp_syn_cache_size", 8191);
    u_stack_tick();
    puts("SYN-cache startup sizing and live resize rejection passed");
    return 0;
}
