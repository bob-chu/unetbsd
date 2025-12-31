#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mbuf.h>
#include <rte_mempool.h> // New include
#include <rte_common.h> // For RTE_SET_USED
#include <rte_lcore.h> // For rte_lcore_id
#include <rte_ethdev.h>
#include <rte_memzone.h>

#include "config.h"
#include "logger.h" // Assuming LOG_ERROR, LOG_INFO are here
#include "dpdk_client.h"
#include "u_if.h"
#include "common.h"


#include <stdlib.h>
#include <string.h>

#define NUM_MBUFS 1024
#define MBUF_CACHE_SIZE 256
#define JUMBO_FRAME_MAX_SIZE 9600

// Global rings
struct rte_ring *lb_rx_ring; // Client's RX ring from Load Balancer
struct rte_ring *lb_tx_ring; // Client's TX ring to Load Balancer
struct rte_mempool *pkt_mbuf_pool; // New global mempool

struct lb_shared_info *shared_info;

static struct virt_interface *v_if;
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

int dpdk_client_init(dpdk_config_t *dpdk_config) {
    char dpdk_args[512];
    snprintf(dpdk_args, sizeof(dpdk_args), "-l%d --proc-type=secondary --file-prefix=%s",
             dpdk_config->core_id, dpdk_config->iface);

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

    enum rte_proc_type_t proc_type = rte_eal_process_type();
    unsigned ring_idx = dpdk_config->client_ring_idx;

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

    const struct rte_memzone *mz = rte_memzone_lookup(LB_SHARED_MEMZONE);
    if (mz == NULL) {
        LOG_ERROR("Cannot find memzone: %s\n", LB_SHARED_MEMZONE);
        return -1;
    }
    shared_info = (struct lb_shared_info *)mz->addr;


    // Lookup or create Mbuf Pool based on process type
    if (proc_type == RTE_PROC_PRIMARY) {
        // Assuming single port and single process for client if it's primary
        unsigned int num_mbufs = NUM_MBUFS + MBUF_CACHE_SIZE + BURST_SIZE; 
        pkt_mbuf_pool = rte_pktmbuf_pool_create(PKTMBUF_POOL_NAME, num_mbufs,
            MBUF_CACHE_SIZE, 0, JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
    } else {
        pkt_mbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    }
    
    if (pkt_mbuf_pool == NULL) {
        LOG_ERROR("Cannot find or create Mbuf pool: %s\n", PKTMBUF_POOL_NAME);
        return -1;
    }
    LOG_INFO("Found Mbuf pool: %s:%p\n", PKTMBUF_POOL_NAME, pkt_mbuf_pool);

    // Set lcore ID
    LOG_INFO("DPDK client configured to use lcore_id: %d\n", dpdk_config->client_lcore_id);

    return 0;
}

uint16_t dpdk_client_read(void) {
    uint16_t i, rx_pkts;
    struct rte_mbuf *bufs_local[BURST_SIZE];
    if (lb_rx_ring == NULL) {
        LOG_ERROR("lb_rx_ring is NULL, cannot read packets.\n");
        return 0;
    }
    rx_pkts = rte_ring_dequeue_burst(lb_rx_ring, (void **)bufs_local, BURST_SIZE, NULL);
    if (unlikely(rx_pkts == 0)) return 0;

    for (i = 0; i < rx_pkts; i++) {
        struct rte_mbuf *buf = bufs_local[i];
        dump_mbuf_hex(buf, "IN");
        single_mbuf_input(buf);
    }
    return rx_pkts;
}

int dpdk_client_send_packet(struct rte_mbuf *m) {
    if (lb_tx_ring == NULL) {
        LOG_ERROR("lb_tx_ring is NULL, dropping packet.\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    dump_mbuf_hex(m, "OUT");
    if (rte_ring_enqueue(lb_tx_ring, m) != 0) {
        LOG_ERROR("Failed to enqueue packet to TX ring, dropping.\n");
        rte_pktmbuf_free(m);
        return -1;
    }
    return 0;
}

int dpdk_client_if_output(void *m, long unsigned int total, void *arg)
{
#define MAX_OUT_MBUFS 8
    struct iovec iov[MAX_OUT_MBUFS];
    int i, len, count;
    char *data;

    //count = array_size(iov);
    count = sizeof(iov)/sizeof(iov[0]);

    len = netbsd_mbufvec(m, iov, &count);
    if (len == 0) {
        goto out;
    }

    struct rte_mbuf *buf = rte_pktmbuf_alloc(pkt_mbuf_pool);
    if (buf == NULL) {
        goto out;
    }
    for (i = 0; i < count; i++) {
        data = rte_pktmbuf_append(buf, iov[i].iov_len);
        if (!data) {
            rte_pktmbuf_free(buf);
            break;
        }
        rte_memcpy(data, iov[i].iov_base, iov[i].iov_len);
    }

    return dpdk_client_send_packet(buf);

out:
    return 0;
}


/*
 * virt_interface
 */
void open_dpdk_client_interface(char *if_name)
{
    v_if = virt_if_create(if_name);
    virt_if_attach(v_if, (const uint8_t *)&shared_info->port_mac);

    virt_if_register_callbacks(v_if, dpdk_client_if_output, NULL);
}


struct lb_shared_info* get_lb_shared_info(void) {
    return shared_info;
}

