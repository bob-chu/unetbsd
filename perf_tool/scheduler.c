#include "scheduler.h"
#include "logger.h"
#include "metrics.h"
#include "client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static perf_config_t *g_config;
static struct ev_loop *g_loop;

static scheduler_stats_t g_stats = {0};
static scheduler_stats_t last_stats = {0};
static metrics_t last_metrics = {0};
static int time_index = 0;

static double g_start_time;
static double g_current_phase_start_time;

static test_phase_t g_current_phase = PHASE_PREPARE;

static const char *phase_names[] = {
    "prepare",
    "ramp_up",
    "sustain",
    "ramp_down",
    "close",
    "finished"
};

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

uint64_t g_concurrent_connections = 0;

void scheduler_inc_stat(int stat, int value) {
    switch (stat) {
        case STAT_CONCURRENT_CONNECTIONS:
            g_concurrent_connections += value;
            break;
        case STAT_CONNECTIONS_OPENED:
            g_stats.connections_opened += value;
            break;
        case STAT_CONNECTIONS_CLOSED:
            g_stats.connections_closed += value;
            break;
        case STAT_REQUESTS_SENT:
            g_stats.requests_sent += value;
            break;
        case STAT_RESPONSES_RECEIVED:
            g_stats.responses_received += value;
            break;
        case STAT_BYTES_SENT:
            g_stats.bytes_sent += value;
            break;
        case STAT_BYTES_RECEIVED:
            g_stats.bytes_received += value;
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

const scheduler_stats_t *scheduler_get_stats(void) {
    return &g_stats;
}

double scheduler_get_current_time(void) {
    return ev_now(g_loop);
}

double scheduler_get_current_phase_start_time(void) {
    return g_current_phase_start_time;
}

void scheduler_check_phase_transition(const char *role) {
    double now = ev_now(g_loop);
    double total_elapsed_time = now - g_start_time;

    metrics_t current_metrics = metrics_get_snapshot();
    const scheduler_stats_t *current_stats = scheduler_get_stats();

    uint64_t connections_per_second = (current_stats->connections_opened - last_stats.connections_opened);
    uint64_t requests_per_second = (current_stats->requests_sent - last_stats.requests_sent);
    uint64_t bytes_sent_per_second = (current_stats->bytes_sent - last_stats.bytes_sent);
    uint64_t bytes_received_per_second = (current_stats->bytes_received - last_stats.bytes_received);
    uint64_t success_per_second = (current_metrics.success_count - last_metrics.success_count);
    uint64_t failure_per_second = (current_metrics.failure_count - last_metrics.failure_count);

    printf("[%s] [ %ds], %s (Target: %d), Concurrent Conns: %lu, CPS: %lu, RPS: %lu, BpsS: %lu, BpsR: %lu, Succ: %lu, Fail: %lu\n",
           role,
           time_index,
           phase_names[g_current_phase],
           client_get_current_target_connections(),
           g_concurrent_connections,
           connections_per_second,
           requests_per_second,
           bytes_sent_per_second,
           bytes_received_per_second,
           success_per_second,
           failure_per_second);

    last_stats = *current_stats;
    last_metrics = current_metrics;
    time_index++;

    if (strcmp(g_config->objective.type, "TOTAL_CONNECTIONS") == 0) {
        if (g_stats.connections_opened >= g_config->objective.value) {
            //LOG_INFO("TOTAL_CONNECTIONS objective reached. Test finished. Stopping event loop.");
            //g_current_phase = PHASE_FINISHED;
            //ev_break(g_loop, EVBREAK_ALL);
            //return; // Exit early
        }
    } else if (strcmp(g_config->objective.type, "HTTP_REQUESTS") == 0) {
        if (g_stats.responses_received >= g_config->objective.value) {
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
