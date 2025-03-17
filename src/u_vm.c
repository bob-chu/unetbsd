#include <sys/vmem_impl.h>
#include <sys/kmem.h>

vmem_t *kmem_arena;
vmem_t *kmem_va_arena;

void vm_init()
{
	kmem_arena = vmem_create("kmem", 0, 1024*1024, PAGE_SIZE,
	    NULL, NULL, NULL,
	    0, VM_NOSLEEP | VM_BOOTSTRAP, IPL_VM);

	vmem_subsystem_init(kmem_arena);

	kmem_va_arena = vmem_create("kva", 0, 0, PAGE_SIZE,
	    vmem_alloc, vmem_free, kmem_arena,
	    8 * PAGE_SIZE, VM_NOSLEEP | VM_BOOTSTRAP, IPL_VM);
}
