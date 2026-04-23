#ifndef STATS_CGO_H
#define STATS_CGO_H

#include <stdint.h>

typedef struct {
    uint64_t connections_opened;
    uint64_t connections_closed;
    uint64_t requests_sent;
    uint64_t responses_received;
    uint64_t tcp_concurrent;

    // HTTP Stats
    uint64_t http_conn_fails;
    uint64_t http_req_sent;
    uint64_t http_req_rcvd;
    uint64_t http_rep_hdr_parse_err;
    uint64_t http_rsp_bad_hdrs;
    uint64_t http_rsp_hdr_overflow;
    uint64_t http_rsp_hdr_parse_err_duplicate; // Renamed to avoid duplicate field in Go
    uint64_t http_rsp_recv_full;
    uint64_t http_rsp_hdr_send;
    uint64_t http_rsp_hdr_send_err;
    uint64_t http_rsp_body_send;
    uint64_t http_rsp_body_send_err;
    uint64_t http_rsp_body_send_done;
    uint64_t http_alloc_pool;
    uint64_t http_return_pool;

    // TCP Stats
    uint64_t tcp_cli_open_req;
    uint64_t tcp_cli_open_req_done;
    uint64_t tcp_cli_open_ack_ok;
    uint64_t tcp_cli_open_ack_failed;
    uint64_t tcp_cli_close_req;
    uint64_t tcp_cli_close_req_netbsd;
    uint64_t tcp_cli_close_cb;
    uint64_t tcp_svr_accept_req;
    uint64_t tcp_svr_accept_netbsd;
    uint64_t tcp_svr_accept_netbsd_ok;
    uint64_t tcp_bytes_sent;
    uint64_t tcp_bytes_received;
    uint64_t tcp_alloc_pool;
    uint64_t tcp_return_pool;

    // UDP Stats
    uint64_t udp_bytes_sent;
    uint64_t udp_bytes_received;
} stats_t;

#endif // STATS_CGO_H