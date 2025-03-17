#ifndef _AMD64_CPU_H_
#define _AMD64_CPU_H_

#ifdef __x86_64__
#include <x86/cpu.h>
static struct cpu_info *x86_curcpu(void);
static lwp_t *x86_curlwp(void);
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Warray-bounds"

extern struct cpu_info cpu0;
//__inline __always_inline static struct cpu_info * __unused __nomsan
static struct cpu_info *
x86_curcpu(void)
{
	static struct cpu_info *ci = &cpu0;

	return ci;
}

extern lwp_t *gl_lwp;

//__inline static lwp_t * __unused __nomsan __attribute__ ((const))
__inline static lwp_t * __unused __nomsan
x86_curlwp(void)
{
	lwp_t *l = gl_lwp;

	return l;
}


#endif

#endif /* !_AMD64_CPU_H_ */
