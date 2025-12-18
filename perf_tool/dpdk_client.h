#ifndef DPDK_CLIENT_H
#define DPDK_CLIENT_H

#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h> // New include for rte_mempool
#include "../perf_tool/config.h" // For perf_config_t

#define BURST_SIZE 32
#define PKTMBUF_POOL_NAME "MBUF_POOL"

// Forward declarations for functions
int dpdk_client_init(perf_config_t *config);
uint16_t dpdk_client_read(void);
int dpdk_client_send_packet(struct rte_mbuf *m);
void open_dpdk_client_interface(char *if_name, char *mac_addr_str);

// External declarations for rings and mempool
extern struct rte_ring *lb_rx_ring;
extern struct rte_ring *lb_tx_ring;
extern struct rte_mempool *pkt_mbuf_pool; // New extern declaration

#endif // DPDK_CLIENT_H
