#include "stub.h"
#include <sys/percpu.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_private.h>
#include "u_tcp_stat.h"

extern percpu_t *tcpstat_percpu;
extern struct cpu_info cpu0;

static const char *tcp_stat_names[] = {
    "connections initiated",
    "connections accepted",
    "connections established",
    "connections dropped",
    "embryonic connections dropped",
    "conn. closed (includes drops)",
    "segs where we tried to get rtt",
    "times we succeeded",
    "delayed ACKs sent",
    "conn. dropped in rxmt timeout",
    "retransmit timeouts",
    "persist timeouts",
    "keepalive timeouts",
    "keepalive probes sent",
    "connections dropped in keepalive",
    "connections dropped in persist",
    "connections drained due to memory shortage",
    "PMTUD blackhole detected",
    "total packets sent",
    "data packets sent",
    "data bytes sent",
    "data packets retransmitted",
    "data bytes retransmitted",
    "ACK-only packets sent",
    "window probes sent",
    "packets sent with URG only",
    "window update-only packets sent",
    "control (SYN|FIN|RST) packets sent",
    "total packets received",
    "packets received in sequence",
    "bytes received in sequence",
    "packets received with cksum errs",
    "packets received with bad offset",
    "packets dropped for lack of memory",
    "packets received too short",
    "duplicate-only packets received",
    "duplicate-only bytes received",
    "packets with some duplicate data",
    "dup. bytes in part-dup. packets",
    "out-of-order packets received",
    "out-of-order bytes received",
    "packets with data after window",
    "bytes received after window",
    "packets received after \"close\"",
    "rcvd window probe packets",
    "rcvd duplicate ACKs",
    "rcvd ACKs for unsent data",
    "rcvd ACK packets",
    "bytes ACKed by rcvd ACKs",
    "rcvd window update packets",
    "segments dropped due to PAWS",
    "times hdr predict OK for ACKs",
    "times hdr predict OK for data pkts",
    "input packets missing PCB hash",
    "no socket on port",
    "received ACK for which we have no SYN in compressed state",
    "delayed pool_put() of tcpcb",
    "# of sc entries added",
    "# of sc connections completed",
    "# of sc entries timed out",
    "# of sc drops due to overflow",
    "# of sc drops due to RST",
    "# of sc drops due to ICMP unreach",
    "# of sc drops due to bucket ovflow",
    "# of sc entries aborted (no mem)",
    "# of duplicate SYNs received",
    "# of SYNs dropped (no route/mem)",
    "# of sc hash collisions",
    "# of sc retransmissions",
    "# of delayed pool_put()s",
    "# of ENOBUFS we get on output",
    "# of drops due to bad signature",
    "# of packets with good signature",
    "# of successful ECN handshakes",
    "# of packets with CE bit",
    "# of packets with ECT(0) bit",
};

const char *unetbsd_get_tcp_stat_name(int index) {
    if (index < 0 || index >= UNETBSD_TCP_NSTATS) {
        return NULL;
    }
    return tcp_stat_names[index];
}

int unetbsd_get_tcp_stats(uint64_t *stats, size_t *len) {
    if (!stats || !len) {
        return -1;
    }

    if (*len < UNETBSD_TCP_NSTATS) {
        *len = UNETBSD_TCP_NSTATS;
        return -1;
    }

    if (!tcpstat_percpu) {
        return -2;
    }

    uint64_t *internal_stats = (uint64_t *)percpu_getptr_remote(tcpstat_percpu, &cpu0);
    if (!internal_stats) {
        return -3;
    }

    memcpy(stats, internal_stats, sizeof(uint64_t) * UNETBSD_TCP_NSTATS);
    *len = UNETBSD_TCP_NSTATS;
    return 0;
}
