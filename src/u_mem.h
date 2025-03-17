#ifndef __U_MEM_H__
#define __U_MEM_H__
#undef malloc
#undef free
extern void *malloc (size_t __size);
extern void *memalign (size_t __alignment, size_t __size);
extern void free (void *__ptr);
extern void *memset(void *s, int c, size_t n);
extern void *calloc(size_t nmemb, size_t size);
void *memcpy(void *dest, const void *src, size_t n);

#define  u_malloc malloc
#define  u_free free
#define  u_memset memset
#define  u_memcpy memcpy

#endif
