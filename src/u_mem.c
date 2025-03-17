#include <sys/param.h>
#include <sys/systm.h>
#include <sys/percpu.h>

#include <sys/thmap.h>
#include <sys/once.h>
#include <sys/kernel.h>
#include <sys/xcall.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
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
#include <sys/queue.h>
#include <sys/pool.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_stats.h>
#include <netinet/in.h>
#include "u_mem.h"

const char *panicstr = NULL;
vmem_t *kmem_va_arena = NULL;
vmem_t *kmem_meta_arena = NULL;
vmem_t *kmem_arena = NULL;
#if 1
int vmem_alloc(vmem_t *vm, vmem_size_t size, vm_flag_t flags, vmem_addr_t *addrp) {
    *addrp = (vmem_addr_t)calloc(1, size);
    return *addrp ? 0 : ENOMEM;
}
void vmem_free(vmem_t *vm, vmem_addr_t addr, vmem_size_t size) { free((void *)addr); }
#endif
#if 0
int uvm_km_kmem_alloc(vmem_t *vm, vmem_size_t size, vm_flag_t flags, vmem_addr_t *addrp) {
    *addrp = (vmem_addr_t)calloc(1, size);
    return *addrp ? 0 : ENOMEM;
}
void uvm_km_kmem_free(vmem_t *vm, vmem_addr_t addr, vmem_size_t size) { free((void *)addr); }
#endif
void
uvm_kick_pdaemon()
{
}

#define USER_PAGE_SIZE 4096 
/*
struct pool_item_header {
    void *ph_page;
    LIST_ENTRY(pool_item_header) ph_list;
};
*/
//struct pool_item_header;
//static LIST_HEAD(, pool_item_header) user_page_list = LIST_HEAD_INITIALIZER(user_page_list);

typedef uint32_t pool_item_bitmap_t;
struct pool_item_header {
	/* Page headers */
	LIST_ENTRY(pool_item_header)
				ph_pagelist;	/* pool page list */
	union {
		/* !PR_PHINPAGE */
		struct {
			SPLAY_ENTRY(pool_item_header)
				phu_node;	/* off-page page headers */
		} phu_offpage;
		/* PR_PHINPAGE */
		struct {
			unsigned int phu_poolid;
		} phu_onpage;
	} ph_u1;
	void *			ph_page;	/* this page's address */
	uint32_t		ph_time;	/* last referenced */
	uint16_t		ph_nmissing;	/* # of chunks in use */
	uint16_t		ph_off;		/* start offset in page */
	union {
		/* !PR_USEBMAP */
		struct {
			LIST_HEAD(, pool_item)
				phu_itemlist;	/* chunk list for this page */
		} phu_normal;
		/* PR_USEBMAP */
		struct {
			pool_item_bitmap_t phu_bitmap[1];
		} phu_notouch;
	} ph_u2;
};


int
uvm_km_kmem_alloc(vmem_t *vm, vmem_size_t size, vm_flag_t flags, vmem_addr_t *addrp)
{
    void *ptr;
    if (posix_memalign(&ptr, USER_PAGE_SIZE, size) != 0) {
        printf("uvm_km_kmem_alloc: posix_memalign failed for %zu\n", size);
        *addrp = 0;
        return ENOMEM;
    }
    memset(ptr, 0, size); /* 模拟 calloc */

    /* 页面头部放在页面开头 */
    struct pool_item_header *ph = ptr;
    ph->ph_page = ptr; /* ph_page 是页面基地址 */

    *addrp = (vmem_addr_t)ph->ph_page;
    printf("uvm_km_kmem_alloc: allocated %p (size=%zu)\n", (void *)*addrp, size);
    return 0;
}

void
uvm_km_kmem_free(vmem_t *vm, vaddr_t addr, vmem_size_t size)
{
    struct pool_item_header *ph;
#if 1
    void *ptr = (void *)addr;

    free(ptr);
#else
    LIST_FOREACH(ph, &user_page_list, ph_list) {
        if (ph->ph_page == (void *)addr) {
            LIST_REMOVE(ph, ph_list);
            free(ph);
            printf("uvm_km_kmem_free: freed %p (size=%zu)\n", (void *)addr, size);
            return;
        }
    }
#endif
    printf("uvm_km_kmem_free: address %p not found\n", (void *)addr);
}


