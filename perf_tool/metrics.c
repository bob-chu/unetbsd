#include "metrics.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static metrics_t g_metrics;
static uint64_t g_latency_sum;
static uint64_t g_latency_count;

void metrics_init(void) {
    memset(&g_metrics, 0, sizeof(metrics_t));
    g_metrics.min_latency_ms = -1; // Initialize with a very large value
    g_metrics.total_ports = 65536; // Assuming a default total number of ports, adjust as needed
    g_latency_sum = 0;
    g_latency_count = 0;
    LOG_INFO("Metrics initialized.");
}

void metrics_report(void) {
    printf("\n--- Performance Metrics Report ---");
    printf("Connections per second: %lu", g_metrics.connections_per_second);
    printf("Bytes Sent per second: %lu (%.2f Mbps)", g_metrics.bytes_sent_per_second, (g_metrics.bytes_sent_per_second * 8.0) / 1000000.0);
    printf("Bytes Received per second: %lu (%.2f Mbps)", g_metrics.bytes_received_per_second, (g_metrics.bytes_received_per_second * 8.0) / 1000000.0);
    printf("Successful operations: %lu", g_metrics.success_count);
    printf("Failed operations: %lu", g_metrics.failure_count);
    printf("Ports Used: %lu/%lu", g_metrics.ports_used, g_metrics.total_ports);

    if (g_latency_count > 0) {
        g_metrics.avg_latency_ms = g_latency_sum / g_latency_count;
        printf("Min Latency (ms): %lu", g_metrics.min_latency_ms);
        printf("Max Latency (ms): %lu", g_metrics.max_latency_ms);
        printf("Avg Latency (ms): %lu", g_metrics.avg_latency_ms);
    } else {
        printf("No latency data available.");
    }
    printf("----------------------------------");
}

void metrics_inc_success(void) {
    g_metrics.success_count++;
}

void metrics_inc_failure(void) {
    g_metrics.failure_count++;
}

void metrics_add_latency(uint64_t latency_ms) {
    if (latency_ms < g_metrics.min_latency_ms) {
        g_metrics.min_latency_ms = latency_ms;
    }
    if (latency_ms > g_metrics.max_latency_ms) {
        g_metrics.max_latency_ms = latency_ms;
    }
    g_latency_sum += latency_ms;
    g_latency_count++;
}

metrics_t metrics_get_snapshot(void) {
    metrics_t snapshot = g_metrics;
    if (g_latency_count > 0) {
        snapshot.avg_latency_ms = g_latency_sum / g_latency_count;
    }
    return snapshot;
}

void metrics_update_port_usage(uint64_t ports_used, uint64_t total_ports) {
    g_metrics.ports_used = ports_used;
    g_metrics.total_ports = total_ports;
    LOG_INFO("Updated port usage: %lu/%lu", ports_used, total_ports);
}

void metrics_update_cps(uint64_t cps) {
    g_metrics.connections_per_second = cps;
}

void metrics_update_bytes_sent(uint64_t bytes) {
    g_metrics.total_bytes_sent += bytes;
    g_metrics.bytes_sent_per_second += bytes;
}

void metrics_update_bytes_received(uint64_t bytes) {
    g_metrics.total_bytes_received += bytes;
    g_metrics.bytes_received_per_second += bytes;
}

void metrics_reset_bytes_per_second(void) {
    g_metrics.bytes_sent_per_second = 0;
    g_metrics.bytes_received_per_second = 0;
}
