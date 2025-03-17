#ifndef _U_LWP_H_
#define _U_LWP_H_
// 包含 NetBSD 的原始 lwp.h
#include_next <sys/lwp.h>

// 覆盖 curlwp_bind 定义
#ifdef curlwp_bind
#undef curlwp_bind
#endif
#define curlwp_bind()  (0) // 空实现
                           //
// 覆盖 curlwp_bindx
#ifdef curlwp_bindx
#undef curlwp_bindx
#endif
#define curlwp_bindx(flags) (0)
#endif /* _U_LWP_H_ */
