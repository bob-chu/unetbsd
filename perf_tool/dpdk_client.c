#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h> // New include
#include <rte_common.h> // For RTE_SET_USED
#include <rte_lcore.h> // For rte_lcore_id

#include "config.h"
#include "logger.h" // Assuming LOG_ERROR, LOG_INFO are here
#include "dpdk_client.h"

#include <stdlib.h>
#include <string.h>

// Global rings
struct rte_ring *lb_rx_ring; // Client's RX ring from Load Balancer
struct rte_ring *lb_tx_ring; // Client's TX ring to Load Balancer
struct rte_mempool *pkt_mbuf_pool; // New global mempool

// Helper to get RX ring name from Load Balancer's perspective
static const char *get_rx_queue_name_lb(unsigned id) {
    /* Use a unique name for each ring. */
    static char buf[RTE_RING_NAMESIZE];
    snprintf(buf, sizeof(buf), "LB_RX_RING_%u", id);
    return buf;
}

// Helper to get TX ring name from Load Balancer's perspective
static const char *get_tx_queue_name_lb(unsigned id) {
    /* Use a unique name for each ring. */
    static char buf[RTE_RING_NAMESIZE];
    snprintf(buf, sizeof(buf), "LB_TX_RING_%u", id);
    return buf;
}

int dpdk_client_init(perf_config_t *config) {
    char dpdk_args[512];
    snprintf(dpdk_args, sizeof(dpdk_args), "-l%d %s", config->dpdk.core_id, config->dpdk.args);

    char *dpdk_args_copy = strdup(dpdk_args);
    char *dpdk_argv[64];
    int dpdk_argc = 0;
    dpdk_argv[dpdk_argc++] = "perf_tool"; // Dummy program name
    char *token = strtok(dpdk_args_copy, " ");
    while (token != NULL && dpdk_argc < 63) {
        dpdk_argv[dpdk_argc++] = token;
        token = strtok(NULL, " ");
    }
    dpdk_argv[dpdk_argc] = NULL;

    // Initialize EAL
    int ret = rte_eal_init(dpdk_argc, dpdk_argv);
    if (ret < 0) {
        LOG_ERROR("Failed to initialize EAL for DPDK client\n");
        free(dpdk_args_copy);
        return -1;
    }
    free(dpdk_args_copy);

    unsigned ring_idx = config->dpdk.client_ring_idx;

    // Lookup RX ring
    const char *rx_ring_name = get_rx_queue_name_lb(ring_idx);
    lb_rx_ring = rte_ring_lookup(rx_ring_name);
    if (lb_rx_ring == NULL) {
        LOG_ERROR("Cannot find RX ring: %s\n", rx_ring_name);
        return -1;
    }
    LOG_INFO("Found RX ring: %s:%p\n", rx_ring_name, lb_rx_ring);

    // Lookup TX ring
    const char *tx_ring_name = get_tx_queue_name_lb(ring_idx);
    lb_tx_ring = rte_ring_lookup(tx_ring_name);
    if (lb_tx_ring == NULL) {
        LOG_ERROR("Cannot find TX ring: %s\n", tx_ring_name);
        return -1;
    }
    LOG_INFO("Found TX ring: %s:%p\n", tx_ring_name, lb_tx_ring);

    // Lookup Mbuf Pool
    pkt_mbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pkt_mbuf_pool == NULL) {
        LOG_ERROR("Cannot find Mbuf pool: %s\n", PKTMBUF_POOL_NAME);
        return -1;
    }
    LOG_INFO("Found Mbuf pool: %s:%p\n", PKTMBUF_POOL_NAME, pkt_mbuf_pool);

    // Set lcore ID
    LOG_INFO("DPDK client configured to use lcore_id: %d\n", config->dpdk.client_lcore_id);

    return 0;
}

uint16_t dpdk_client_read(perf_config_t *config, struct rte_mbuf **bufs) {
    RTE_SET_USED(config); // To suppress unused warning if config is not used in this function
    if (lb_rx_ring == NULL) {
        LOG_ERROR("lb_rx_ring is NULL, cannot read packets.\n");
        return 0;
    }
    return rte_ring_dequeue_burst(lb_rx_ring, (void **)bufs, BURST_SIZE, NULL);
}

int dpdk_client_send_packet(struct rte_mbuf *m) {
    if (lb_tx_ring == NULL) {
        LOG_ERROR("lb_tx_ring is NULL, dropping packet.\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    if (rte_ring_enqueue(lb_tx_ring, m) != 0) {
        LOG_ERROR("Failed to enqueue packet to TX ring, dropping.\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    return 0;
}
