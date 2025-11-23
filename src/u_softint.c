/*
 * Soft interrupt simulation for userspace NetBSD TCP stack porting.
 * Based on the approach in netbsd_src/sys/rump/librump/rumpkern/intr.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/intr.h>
#include <sys/cpu.h>

#include "u_softint.h"

#define SOFTINT_MAX_COUNT 1024*32
#define SOFTINT_LEVEL_COUNT SOFTINT_COUNT

struct softint_percpu {
    struct softint *sip_parent;
    bool sip_onlist;
    TAILQ_ENTRY(softint_percpu) sip_entries; /* scheduled */
};

struct softint_lev {
    int count;
    TAILQ_HEAD(, softint_percpu) si_pending;
};

struct softint {
    void (*si_func)(void *);
    void *si_arg;
    int si_flags;
    int si_level;
    struct softint_percpu si_entry; /* Per-CPU entry, simplified for single CPU */
};

static struct softint_lev softint_levels[SOFTINT_LEVEL_COUNT];

/*
 * Initialize soft interrupt levels.
 */
void
softint_levels_init(void)
{
    int i;
    for (i = 0; i < SOFTINT_LEVEL_COUNT; i++) {
        TAILQ_INIT(&softint_levels[i].si_pending);
        softint_levels[i].count = 0;
    }
}

/*
 * Execute pending soft interrupts for a given level.
 */
static void
execute_softints(int level, int pending_count)
{
    struct softint_percpu *sip;
    struct softint *si;
    void (*func)(void *);
    void *arg;
    //bool mpsafe;

    while (!TAILQ_EMPTY(&softint_levels[level].si_pending) && pending_count-- > 0) {
        sip = TAILQ_FIRST(&softint_levels[level].si_pending);
        si = sip->sip_parent;

        func = si->si_func;
        arg = si->si_arg;
        //mpsafe = si->si_flags & SI_MPSAFE;

        sip->sip_onlist = false;
        TAILQ_REMOVE(&softint_levels[level].si_pending, sip, sip_entries);
#if 0
        if (!mpsafe) {
            // In a real kernel, this would lock the kernel, but in userspace, it's a no-op
            printf("Executing non-MPSAFE soft interrupt at level %d\n", level);
        }
#endif
        func(arg);
#if 0
        if (!mpsafe) {
            // Unlock if needed, no-op in userspace
            printf("Finished non-MPSAFE soft interrupt at level %d\n", level);
        }
#endif
    }
}

/*
 * Establish a soft interrupt handler.
 */
void *
softint_establish(u_int flags, void (*func)(void *), void *arg)
{
    struct softint *si;
    int level = flags & SOFTINT_LVLMASK;

    if (level >= SOFTINT_LEVEL_COUNT) {
        printf("Invalid soft interrupt level: %d\n", level);
        return NULL;
    }

    si = malloc(sizeof(*si), M_TEMP, M_WAITOK);
    if (si == NULL) {
        printf("Failed to allocate soft interrupt structure\n");
        return NULL;
    }

    si->si_func = func;
    si->si_arg = arg;
    si->si_flags = flags & SOFTINT_MPSAFE ? SI_MPSAFE : 0;
    si->si_level = level;
    si->si_entry.sip_parent = si;
    si->si_entry.sip_onlist = false;

    //printf("Established soft interrupt at level %d\n", level);
    return si;
}

/*
 * Disestablish a soft interrupt handler.
 */
void
softint_disestablish(void *cook)
{
    struct softint *si = cook;
    struct softint_percpu *sip = &si->si_entry;

    if (sip->sip_onlist) {
        printf("Warning: Disestablishing active soft interrupt at level %d\n", si->si_level);
        TAILQ_REMOVE(&softint_levels[si->si_level].si_pending, sip, sip_entries);
        sip->sip_onlist = false;
    }

    free(si, M_TEMP);
    printf("Disestablished soft interrupt\n");
}

/*
 * Schedule a soft interrupt to be executed later.
 */
void
softint_schedule(void *arg)
{
    struct softint *si = arg;
    struct softint_percpu *sip = &si->si_entry;

    if (!sip->sip_onlist) {
        TAILQ_INSERT_TAIL(&softint_levels[si->si_level].si_pending, sip, sip_entries);
        softint_levels[si->si_level].count++;
        sip->sip_onlist = true;
        //printf("Scheduled soft interrupt at level %d\n", si->si_level);
    } else {
        //printf("Soft interrupt at level %d already scheduled\n", si->si_level);
    }
    //softint_run();
}

/*
 * Schedule a soft interrupt on a specific CPU (simplified for single CPU in userspace).
 */
void
softint_schedule_cpu(void *arg, struct cpu_info *ci_tgt)
{
    // In userspace, ignore CPU target as we are single-threaded
    softint_schedule(arg);
}

/*
 * Run pending soft interrupts for all levels.
 */
void
softint_run(void)
{
    int i;
    int pending_count[SOFTINT_LEVEL_COUNT];
    for (i = 0; i < SOFTINT_LEVEL_COUNT; i++) {
        pending_count[i] = softint_levels[i].count;
    }
    for (i = 0; i < SOFTINT_LEVEL_COUNT; i++) {
        if (!TAILQ_EMPTY(&softint_levels[i].si_pending)) {
            execute_softints(i, pending_count[i]);
        }
    }
}
