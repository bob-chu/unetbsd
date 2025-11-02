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
    g_latency_sum = 0;
    g_latency_count = 0;
    LOG_INFO("Metrics initialized.");
}

void metrics_report(void) {
    LOG_INFO("\n--- Performance Metrics Report ---");
    LOG_INFO("Connections per second: %lu", g_metrics.connections_per_second);
    LOG_INFO("Throughput (Gbps): %lu", g_metrics.throughput_gbps);
    LOG_INFO("Successful operations: %lu", g_metrics.success_count);
    LOG_INFO("Failed operations: %lu", g_metrics.failure_count);

    if (g_latency_count > 0) {
        g_metrics.avg_latency_ms = g_latency_sum / g_latency_count;
        LOG_INFO("Min Latency (ms): %lu", g_metrics.min_latency_ms);
        LOG_INFO("Max Latency (ms): %lu", g_metrics.max_latency_ms);
        LOG_INFO("Avg Latency (ms): %lu", g_metrics.avg_latency_ms);
    } else {
        LOG_INFO("No latency data available.");
    }
    LOG_INFO("----------------------------------");
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