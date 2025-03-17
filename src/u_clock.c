#include "stub.h"
#include "sys/callout.h"

extern int clock_gettime(clockid_t clock_id, struct timespec *tp);
/* 时间相关函数 */
//void hardclock(void);  /* 模拟硬时钟 */

/* callout 相关全局变量 */

/* 时间相关函数 */
void gettime(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

void netbsd_time_init()
{
}

void user_hardclock() {
    callout_hardclock();  /* 调用 kern_time.c 中的 callout_hardclock */
}
