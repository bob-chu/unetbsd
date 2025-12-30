#include "scheduler.h"
#include "logger.h"
#include "metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static perf_config_t *g_config;
static struct ev_loop *g_loop;

static stats_t last_stats = {0};
static metrics_t last_metrics = {0};
static int time_index = 0;

static double g_start_time;
static double g_current_phase_start_time;

static test_phase_t g_current_phase = PHASE_PREPARE;
static bool g_scheduler_paused = false; // New: Scheduler paused state

static const char *phase_names[] = {
    "prepare",
    "ramp_up",
    "sustain",
    "ramp_down",
    "close",
    "finished"
};

void scheduler_set_paused(bool paused) {
    g_scheduler_paused = paused;
    if (paused) {
        LOG_INFO("Scheduler paused.");
    } else {
        LOG_INFO("Scheduler unpaused.");
    }
}

bool scheduler_is_paused(void) {
    return g_scheduler_paused;
}

const char **scheduler_get_phase_names(void) {
    return (const char **)phase_names;
}

void scheduler_init(struct ev_loop *loop, perf_config_t *config) {
    g_loop = loop;
    g_config = config;
    g_start_time = ev_now(g_loop);
    g_current_phase_start_time = g_start_time;
    g_current_phase = PHASE_PREPARE;

    memset(&last_stats, 0, sizeof(scheduler_stats_t));
    memset(&last_metrics, 0, sizeof(metrics_t));
    time_index = 0;

    LOG_INFO("Scheduler initialized. Starting PREPARE phase for %d seconds.", g_config->scheduler.prepare_duration_sec);
}

void scheduler_update_stats(void) {
    // This function can be called periodically to update and log stats
    // For now, we'll just log them at phase transitions.
}

void scheduler_inc_stat(int stat, int value) {
    switch (stat) {
        case STAT_CONCURRENT_CONNECTIONS:
            g_current_stats->tcp_concurrent += value;
            break;
        default:
            LOG_WARN("Unknown scheduler stat: %d", stat);
            break;
    }
}

test_phase_t scheduler_get_current_phase(void) {
    return g_current_phase;
}

void scheduler_set_current_phase(test_phase_t new_phase) {
    g_current_phase = new_phase;
}

const stats_t *scheduler_get_stats(void) {
    return g_current_stats;
}

double scheduler_get_current_time(void) {
    return ev_now(g_loop);
}

double scheduler_get_current_phase_start_time(void) {
    return g_current_phase_start_time;
}

void scheduler_check_phase_transition(const char *role) {
    if (g_scheduler_paused) { // New: Check if scheduler is paused
        LOG_DEBUG("Scheduler is paused, skipping phase transition check.");
        return;
    }
    double now = ev_now(g_loop);
    double total_elapsed_time = now - g_start_time;

    metrics_t current_metrics = metrics_get_snapshot();
    const scheduler_stats_t *current_stats = scheduler_get_stats();

    uint64_t connections_opened_per_second = (current_stats->connections_opened - last_stats.connections_opened);
    uint64_t connections_closed_per_second = (current_stats->connections_closed - last_stats.connections_closed);
    uint64_t requests_per_second = (current_stats->requests_sent - last_stats.requests_sent);
    uint64_t bytes_sent_per_second = (current_stats->tcp_bytes_sent - last_stats.tcp_bytes_sent);
    uint64_t bytes_received_per_second = (current_stats->tcp_bytes_received - last_stats.tcp_bytes_received);
    uint64_t success_per_second = (current_metrics.success_count - last_metrics.success_count);
    uint64_t failure_per_second = (current_metrics.failure_count - last_metrics.failure_count);

    // Update metrics for real-time display with per-second values
    metrics_update_cps(connections_opened_per_second);
    metrics_update_bytes_sent(bytes_sent_per_second);
    metrics_update_bytes_received(bytes_received_per_second);
    
    metrics_t display_metrics = metrics_get_snapshot();

    STATS_SET(time_index, time_index);
    STATS_SET(current_phase, g_current_phase);

    STATS_SET(target_connections, client_get_current_target_connections());
    STATS_SET(tcp_concurrent, g_current_stats->tcp_concurrent);
    STATS_SET(connections_opened, g_current_stats->connections_opened);
    STATS_SET(connections_closed, g_current_stats->connections_closed);
    STATS_SET(requests_sent, g_current_stats->requests_sent);
    STATS_SET(tcp_bytes_sent, g_current_stats->tcp_bytes_sent);
    STATS_SET(tcp_bytes_received, g_current_stats->tcp_bytes_received);
    STATS_SET(success_count, current_metrics.success_count);
    STATS_SET(failure_count, current_metrics.failure_count);

    // Get the current accumulated byte counts from metrics for display

    if (strcmp(role, "client") == 0) {
        printf("[%s] [ %ds], %s (Target: %d), ConConns: %lu, CPS: %lu, Closes/s: %lu, RPS: %lu, BpsS: %.2f Mbps, BpsR: %.2f Mbps, Succ: %lu, Fail: %lu\n",
               role,
               time_index,
               phase_names[g_current_phase],
               client_get_current_target_connections(),
               g_current_stats->tcp_concurrent,
               connections_opened_per_second,
               connections_closed_per_second,
               requests_per_second,
               (display_metrics.bytes_sent_per_second * 8.0) / 1000000.0,
               (display_metrics.bytes_received_per_second * 8.0) / 1000000.0,
               success_per_second,
               failure_per_second);
    } else {
        printf("[%s] [ %ds], %s (Target: %d), ConConns: %lu, CPS: %lu, Closes/s: %lu, RPS: %lu, BpsS: %.2f Mbps, BpsR: %.2f Mbps, Succ: %lu, Fail: %lu\n",
               role,
               time_index,
               phase_names[g_current_phase],
               client_get_current_target_connections(),
               g_current_stats->tcp_concurrent,
               connections_opened_per_second,
               connections_closed_per_second,
               requests_per_second,
               (display_metrics.bytes_sent_per_second * 8.0) / 1000000.0,
               (display_metrics.bytes_received_per_second * 8.0) / 1000000.0,
               success_per_second,
               failure_per_second);
    }

    last_stats = *current_stats;
    last_metrics = current_metrics;
    time_index++;
    
    // Reset per-second metrics after display, so next interval starts fresh
    metrics_reset_bytes_per_second();

    if (strcmp(g_config->objective.type, "TOTAL_CONNECTIONS") == 0) {
        if (g_current_stats->connections_opened >= g_config->objective.value) {
            //LOG_INFO("TOTAL_CONNECTIONS objective reached. Test finished. Stopping event loop.");
            //g_current_phase = PHASE_FINISHED;
            //ev_break(g_loop, EVBREAK_ALL);
            //return; // Exit early
        }
    } else if (strcmp(g_config->objective.type, "HTTP_REQUESTS") == 0) {
        if (g_current_stats->responses_received >= g_config->objective.value) {
            //LOG_INFO("HTTP_REQUESTS objective reached. Test finished. Stopping event loop.");
            //g_current_phase = PHASE_FINISHED;
            //ev_break(g_loop, EVBREAK_ALL);
            //return; // Exit early
        }
    }

    if (g_current_phase == PHASE_PREPARE && total_elapsed_time >= g_config->scheduler.prepare_duration_sec) {
        LOG_INFO("PREPARE phase finished. Elapsed: %.2f seconds.", total_elapsed_time);
        g_current_phase = PHASE_RAMP_UP;
        g_current_phase_start_time = now;
        LOG_INFO("Starting RAMP_UP phase for %d seconds.", g_config->scheduler.ramp_up_duration_sec);
    } else if (g_current_phase == PHASE_RAMP_UP && (now - g_current_phase_start_time) >= g_config->scheduler.ramp_up_duration_sec) {
        LOG_INFO("RAMP_UP phase finished. Elapsed: %.2f seconds.", now - g_current_phase_start_time);
        g_current_phase = PHASE_SUSTAIN;
        g_current_phase_start_time = now;
        LOG_INFO("Starting SUSTAIN phase for %d seconds.", g_config->scheduler.sustain_duration_sec);
    } else if (g_current_phase == PHASE_SUSTAIN && (now - g_current_phase_start_time) >= g_config->scheduler.sustain_duration_sec) {
        LOG_INFO("SUSTAIN phase finished. Elapsed: %.2f seconds.", now - g_current_phase_start_time);
        g_current_phase = PHASE_RAMP_DOWN;
        g_current_phase_start_time = now;
        LOG_INFO("Starting RAMP_DOWN phase for %d seconds.", g_config->scheduler.ramp_down_duration_sec);
    } else if (g_current_phase == PHASE_RAMP_DOWN && (now - g_current_phase_start_time) >= g_config->scheduler.ramp_down_duration_sec) {
        LOG_INFO("RAMP_DOWN phase finished. Elapsed: %.2f seconds.", now - g_current_phase_start_time);
        g_current_phase = PHASE_CLOSE;
        g_current_phase_start_time = now;
        LOG_INFO("Starting CLOSE phase for %d seconds.", g_config->scheduler.close_duration_sec);
    } else if (g_current_phase == PHASE_CLOSE && (now - g_current_phase_start_time) >= g_config->scheduler.close_duration_sec) {
        LOG_INFO("CLOSE phase finished. Elapsed: %.2f seconds.", now - g_current_phase_start_time);
        g_current_phase = PHASE_FINISHED;
        LOG_INFO("Test finished. Stopping event loop.");
        ev_break(g_loop, EVBREAK_ALL);
    }
}
