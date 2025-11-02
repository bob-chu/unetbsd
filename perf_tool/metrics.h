#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

typedef struct {
    uint64_t connections_per_second;
    uint64_t throughput_gbps;
    uint64_t success_count;
    uint64_t failure_count;
    uint64_t min_latency_ms;
    uint64_t max_latency_ms;
    uint64_t avg_latency_ms;
} metrics_t;

void metrics_init(void);
void metrics_report(void);
void metrics_inc_success(void);
void metrics_inc_failure(void);
void metrics_add_latency(uint64_t latency_ms);
metrics_t metrics_get_snapshot(void);

#endif // METRICS_H
