#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

typedef struct {
    uint64_t connections_per_second;
    uint64_t success_count;
    uint64_t failure_count;
    uint64_t min_latency_ms;
    uint64_t max_latency_ms;
    uint64_t avg_latency_ms;
    uint64_t ports_used;
    uint64_t total_ports;
    uint64_t total_bytes_sent;
    uint64_t total_bytes_received;
    uint64_t bytes_sent_per_second;
    uint64_t bytes_received_per_second;
} metrics_t;

void metrics_init(void);
void metrics_report(void);
void metrics_inc_success(void);
void metrics_inc_failure(void);
void metrics_add_latency(uint64_t latency_ms);
metrics_t metrics_get_snapshot(void);
void metrics_update_port_usage(uint64_t ports_used, uint64_t total_ports);
void metrics_update_cps(uint64_t cps);
void metrics_update_bytes_sent(uint64_t bytes);
void metrics_update_bytes_received(uint64_t bytes);
void metrics_reset_bytes_per_second(void);

#endif // METRICS_H
