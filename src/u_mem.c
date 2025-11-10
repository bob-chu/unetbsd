#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/pool.h>
#include "u_mem.h"

const char *panicstr = NULL;
vmem_t *kmem_va_arena = NULL;
vmem_t *kmem_meta_arena = NULL;
vmem_t *kmem_arena = NULL;

void
uvm_kick_pdaemon()
{
}

void *
rump_hypermalloc(size_t howmuch, int alignment, bool waitok, const char *wmsg)
{
    void *ptr;
    if (posix_memalign(&ptr, alignment, howmuch) != 0) {
        if (waitok)
            panic("hypermalloc failed");
        return NULL;
    }
    return ptr;
}

void
rump_hyperfree(void *what, size_t size)
{
    free(what);
}

int
uvm_km_kmem_alloc(vmem_t *vm, vmem_size_t size, vm_flag_t flags,
    vmem_addr_t *addr)
{
	vaddr_t va;
	va = (vaddr_t)rump_hypermalloc(size, PAGE_SIZE,
	    (flags & VM_SLEEP), "kmalloc");

	if (va) {
		*addr = va;
		return 0;
	} else {
		return ENOMEM;
	}
}

void
uvm_km_kmem_free(vmem_t *vm, vmem_addr_t addr, vmem_size_t size)
{

	rump_hyperfree((void *)addr, size);
}

int vmem_alloc(vmem_t *vm, vmem_size_t size, vm_flag_t flags, vmem_addr_t *addrp) {
    *addrp = (vmem_addr_t)rump_hypermalloc(size, 16, (flags & VM_SLEEP), "vmem_alloc");
    return *addrp ? 0 : ENOMEM;
}

void vmem_free(vmem_t *vm, vmem_addr_t addr, vmem_size_t size) {
    rump_hyperfree((void *)addr, size);
}

