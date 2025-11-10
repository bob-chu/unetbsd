/*
 * Header for soft interrupt simulation in userspace NetBSD TCP stack porting.
 */

#ifndef _U_SOFTINT_H_
#define _U_SOFTINT_H_

#include <sys/types.h>
#include <sys/queue.h>

/* Define constants for soft interrupts, avoiding redefinition conflicts */
#ifndef SOFTINT_CLOCK
#define SOFTINT_CLOCK   0x0001  /* clock interrupt */
#endif
#ifndef SOFTINT_BIO
#define SOFTINT_BIO     0x0000  /* block I/O */
#endif
#ifndef SOFTINT_NET
#define SOFTINT_NET     0x0003  /* network */
#endif
#ifndef SOFTINT_SERIAL
#define SOFTINT_SERIAL  0x0002  /* serial */
#endif
#ifndef SOFTINT_TTY
#define SOFTINT_TTY     0x0004  /* terminal */
#endif
#ifndef SOFTINT_COUNT
#define SOFTINT_COUNT   0x0004  /* number of soft interrupt levels */
#endif
#ifndef SOFTINT_LVLMASK
#define SOFTINT_LVLMASK 0x00ff  /* mask for level bits */
#endif
#ifndef SI_MPSAFE
#define SI_MPSAFE       0x0100  /* multi-processor safe */
#endif

struct cpu_info;

void softint_levels_init(void);
void *softint_establish(u_int flags, void (*func)(void *), void *arg);
void softint_disestablish(void *cook);
void softint_schedule(void *arg);
void softint_schedule_cpu(void *arg, struct cpu_info *ci_tgt);
void softint_run(void);

#endif /* _U_SOFTINT_H_ */
