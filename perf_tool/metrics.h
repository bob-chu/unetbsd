#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>

#define METRICS_FIELDS \
    X(connections_per_second) \
    X(connections_per_second_http) \
    X(connections_per_second_https) \
    X(success_count) \
    X(failure_count) \
    X(min_latency_ms) \
    X(max_latency_ms) \
    X(avg_latency_ms) \
    X(ports_used) \
    X(total_ports) \
    X(total_bytes_sent) \
    X(total_bytes_received) \
    X(bytes_sent_per_second) \
    X(bytes_received_per_second)

// Generic macros for core operations
#define INC(STRUCT_VAR, field)   ((STRUCT_VAR).field++)
#define DEC(STRUCT_VAR, field)   ((STRUCT_VAR).field--)
#define ADD(STRUCT_VAR, field, val)   ((STRUCT_VAR).field += (val))
#define SUB(STRUCT_VAR, field, val)   ((STRUCT_VAR).field -= (val))

typedef struct {
#define X(name) uint64_t name;
    METRICS_FIELDS
#undef X
} metrics_t;

extern metrics_t g_metrics;
// Metrics macros using generic operations
#define METRIC_INC(field)   INC(g_metrics, field)
#define METRIC_DEC(field)   DEC(g_metrics, field)
#define METRIC_ADD(field, val)   ADD(g_metrics, field, val)
#define METRIC_SUB(field, val)   SUB(g_metrics, field, val)

#define STATS_FIELDS \
    X(connections_opened) \
    X(connections_closed) \
    X(requests_sent) \
    X(responses_received) \
    X(tcp_concurrent)

#define STATS_HTTP_FIELDS \
    X(http_conn_fails) \
    X(http_req_sent) \
    X(http_req_rcvd) \
    X(http_rep_hdr_parse_err) \
    X(http_rsp_bad_hdrs) \
    X(http_rsp_hdr_overflow) \
    X(http_rsp_hdr_parse_err) \
    X(http_rsp_recv_full) \
    X(http_rsp_hdr_send) \
    X(http_rsp_hdr_send_err) \
    X(http_rsp_body_send) \
    X(http_rsp_body_send_err) \
    X(http_rsp_body_send_done)

#define STATS_TCP_FIELDS \
    X(tcp_cli_open_req) \
    X(tcp_cli_open_req_done) \
    X(tcp_cli_open_ack_ok) \
    X(tcp_cli_open_ack_failed) \
    X(tcp_cli_close_req) \
    X(tcp_cli_close_req_netbsd) \
    X(tcp_cli_close_cb) \
    X(tcp_svr_accept_req) \
    X(tcp_svr_accept_netbsd) \
    X(tcp_svr_accept_netbsd_ok) \
    X(tcp_bytes_sent) \
    X(tcp_bytes_received)

#define STATS_UDP_FIELDS \
    X(udp_bytes_sent) \
    X(udp_bytes_received)

typedef struct {
#define X(name) uint64_t name;
    STATS_FIELDS
    STATS_HTTP_FIELDS
    STATS_TCP_FIELDS
    STATS_UDP_FIELDS
#undef X
} stats_t;

extern stats_t g_stats;
// Stats macros using generic operations
#define STATS_INC(field)        INC(g_stats, field)
#define STATS_DEC(field)        DEC(g_stats, field)
#define STATS_ADD(field, val)   ADD(g_stats, field, val)
#define STATS_SUB(field, val)   SUB(g_stats, field, val)


void metrics_init(void);
void metrics_report(void);
void metrics_inc_success(void);
void metrics_inc_failure(void);
void metrics_add_latency(uint64_t latency_ms);
metrics_t metrics_get_snapshot(void);
void metrics_update_port_usage(uint64_t ports_used, uint64_t total_ports);
void metrics_update_cps(uint64_t cps);
void metrics_update_cps_http(uint64_t cps);
void metrics_update_cps_https(uint64_t cps);
void metrics_update_bytes_sent(uint64_t bytes);
void metrics_update_bytes_received(uint64_t bytes);
void metrics_reset_bytes_per_second(void);

#endif // METRICS_H
