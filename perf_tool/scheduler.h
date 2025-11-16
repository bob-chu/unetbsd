#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "config.h"
#include <ev.h>
#include <stdint.h>

typedef enum {
    STAT_CONCURRENT_CONNECTIONS,
    STAT_CONNECTIONS_OPENED,
    STAT_CONNECTIONS_CLOSED,
    STAT_REQUESTS_SENT,
    STAT_RESPONSES_RECEIVED,
    STAT_BYTES_SENT,
    STAT_BYTES_RECEIVED
} scheduler_stat_t;

typedef enum {
    PHASE_PREPARE,
    PHASE_RAMP_UP,
    PHASE_SUSTAIN,
    PHASE_RAMP_DOWN,
    PHASE_CLOSE,
    PHASE_FINISHED
} test_phase_t;

typedef struct {
    uint64_t connections_opened;
    uint64_t connections_closed;
    uint64_t requests_sent;
    uint64_t responses_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} scheduler_stats_t;

extern uint64_t g_concurrent_connections;

void scheduler_init(struct ev_loop *loop, perf_config_t *config);
void scheduler_update_stats(void);
void scheduler_inc_stat(int stat, int value);
test_phase_t scheduler_get_current_phase(void);
void scheduler_set_current_phase(test_phase_t phase);
const scheduler_stats_t *scheduler_get_stats(void);
double scheduler_get_current_time(void);
double scheduler_get_current_phase_start_time(void);
void scheduler_check_phase_transition(const char *role);

#endif // SCHEDULER_H
