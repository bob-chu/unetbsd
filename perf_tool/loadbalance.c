#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <termios.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_jhash.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_byteorder.h> // Added to resolve RTE_BE16_TO_CPU
#include <rte_errno.h>

#include "cJSON.h"
#include "common.h"

// Custom structure to hold both IPv4 and IPv6 addresses
typedef struct {
    uint8_t family; // AF_INET or AF_INET6
    union {
        uint32_t ipv4;
        uint8_t ipv6[16];
    } addr;
} ip_addr_t;

// Custom hash function for ip_addr_t
static inline uint32_t
ip_addr_hash_func(const void *key, uint32_t key_len, uint32_t init_val)
{
    // rte_jhash is suitable for hashing arbitrary byte arrays.
    // We pass the entire ip_addr_t structure as the key.
    return rte_jhash(key, key_len, init_val);
}

#define RTE_LOGTYPE_LB RTE_LOGTYPE_USER1

#define MAX_CLIENTS 128
#define RX_RING_NAME_TEMPLATE "LB_RX_RING_%u"
#define TX_RING_NAME_TEMPLATE "LB_TX_RING_%u"
#define RING_SIZE (1024)
#define IP_HASH_ENTRIES (1024*2)
#define MAX_EAL_ARGS 64 // Max number of DPDK EAL arguments
#define NUMBER_CLIENT_PER_CORE 32


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define MBUFS_PER_WORKER (RX_RING_SIZE+TX_RING_SIZE)
#define NUM_MBUFS (8191 * 8)
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64 
#define JUMBO_FRAME_MAX_SIZE 9600

#define NB_RX_QUEUES 1
#define NB_TX_QUEUES 1

#define LINK_CHECK_INTERVAL_MS 100
#define MAX_LINK_CHECKS 100 /* 100 * 100ms = 10s */

static volatile sig_atomic_t quit_signal = 0;

static uint32_t num_clients = 0;
struct rte_ring *rx_rings[MAX_CLIENTS];
struct rte_ring *tx_rings[MAX_CLIENTS];
struct rte_hash *ip_to_client_table = NULL;
struct rte_mempool *mbuf_pool = NULL; // Make mbuf_pool global
char *dpdk_config_args = NULL; // Global variable for DPDK config args
static int lb_core_id = 0; // Global variable for core_id
static char *eal_args_array[MAX_EAL_ARGS]; // Array to hold parsed EAL arguments
static int eal_args_count = 0; // Count of parsed EAL arguments
static cJSON *global_clients_json = NULL; // Global cJSON object to hold clients array
// Forward declaration for cleanup
static void cleanup_dpdk_config(void);
static int parse_full_config(const char *path); // Forward declaration


static int init_client_hash_table(void); // Forward declaration for client hash table initialization

/* Check and print the link status of @port_id in up to 2s */
static void check_eth_link_status(uint8_t port_id)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 20 /* 2s (20 * 100ms) in total */
    uint8_t count, print_flag = 0;
    struct rte_eth_link link;

    printf("Checking link status... ");
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        memset(&link, 0, sizeof(link));
        rte_eth_link_get_nowait(port_id, &link);

        if (print_flag == 1) {
            if (link.link_status)
                printf("Port %d Link Up - speed %u Mbps - %s\n", port_id,
                      (unsigned)link.link_speed,
                      (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
                      ("full-duplex") : ("half-duplex"));
            else
                printf("Port %d Link Down.\n", port_id);

            break;
        }

        /* wait and retry if the link is down */
        if (link.link_status == RTE_ETH_LINK_DOWN && count < (MAX_CHECK_TIME - 1)) {
            rte_delay_ms(CHECK_INTERVAL);
        } else {
            print_flag = 1;
        }
    }
}

static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool, struct lb_shared_info *shared_info) {
    struct rte_eth_conf port_conf;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    if (!rte_eth_dev_is_valid_port(port))
        return -1;
    
    // Stop device in case it was not properly stopped
    rte_eth_dev_stop(port);

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));
    // Determine supported RSS hash functions
    uint64_t rss_hf_temp = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;
    port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf_temp & dev_info.flow_type_rss_offloads;

    if (port_conf.rx_adv_conf.rss_conf.rss_hf != 0) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS; // Enable RSS only if hash functions are supported
        RTE_LOG(INFO, LB, "Port %u: Enabled RSS with hash functions: 0x%" PRIx64 "\n", port, port_conf.rx_adv_conf.rss_conf.rss_hf);
    } else {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE; // No RSS if no hash functions are supported
        RTE_LOG(WARNING, LB, "Port %u: No supported RSS hash functions found. Disabling RSS.\n", port);
    }

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        RTE_LOG(ERR, LB, "Error getting device (port %u) info: %s\n", port,
                strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    retval =
        rte_eth_dev_configure(port, NB_RX_QUEUES, NB_TX_QUEUES, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    for (q = 0; q < NB_RX_QUEUES; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < NB_TX_QUEUES; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    rte_eth_dev_set_link_up(0);
    check_eth_link_status(0);

    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    RTE_LOG(INFO, LB,
            "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 "\n",
            port, RTE_ETHER_ADDR_BYTES(&addr));

	shared_info->port_mac = addr;

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;
    return 0;
}

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        RTE_LOG(INFO, LB, "Signal %d received, preparing to exit...\n", signum);
        quit_signal = 1;
    }
}

void dump_mbuf_hex(struct rte_mbuf *mbuf, char *msg)
{
    return;
    if (!mbuf) {
        printf("Invalid mbuf\n");
        return;
    }

    // Get the pointer to the data and the data length
    const uint8_t *data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    uint16_t data_len = rte_pktmbuf_data_len(mbuf);

    printf("Mbuf data dump: %s (length=%u):\n", msg, data_len);

    for (uint16_t i = 0; i < data_len; i++) {
        if (i % 16 == 0) { // Start a new line every 16 bytes
            printf("%04x: ", i);
        }

        printf("%02x ", data[i]);

        if (i % 16 == 15 || i == data_len - 1) { // End of line or end of data
            printf("\n");
        }
    }
}


struct lcore_arg {
	uint16_t queue_id;
};

static int lcore_rxtx(void *arg) {
    struct lcore_arg *l_arg = (struct lcore_arg *)arg;
    const uint16_t queue_id = l_arg->queue_id;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *client_bufs[MAX_CLIENTS][BURST_SIZE];
    uint16_t client_buf_counts[MAX_CLIENTS] = {0};
	struct rte_mbuf *tx_burst_buffer[BURST_SIZE];


    RTE_LOG(INFO, LB, "Starting RX/TX loop on lcore %u, queue %u for %u clients\n",
            lcore_id, queue_id, num_clients);

    while (!quit_signal) {
        /* RX path: Receive from NIC and distribute to clients */
        uint16_t nb_rx = rte_eth_rx_burst(0, queue_id, bufs, BURST_SIZE);
        if (nb_rx > 0) {
            for (uint16_t i = 0; i < nb_rx; i++) {
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                ip_addr_t dst_ip;
                int32_t *client_id_ptr;
                int ret_hash;
                uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

                //memset(&dst_ip, 0, sizeof(ip_addr_t));

                if (eth_type == RTE_ETHER_TYPE_IPV4) {
                    struct rte_ipv4_hdr *ipv4_hdr =
                        rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,
                                                sizeof(struct rte_ether_hdr));
                    dst_ip.family = AF_INET;
                    dst_ip.addr.ipv4 = ipv4_hdr->dst_addr;
                } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
                    struct rte_ipv6_hdr *ipv6_hdr =
                        rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv6_hdr *,
                                                sizeof(struct rte_ether_hdr));
                    dst_ip.family = AF_INET6;
                    memcpy(dst_ip.addr.ipv6, ipv6_hdr->dst_addr.a, sizeof(ipv6_hdr->dst_addr.a));
                } else if (eth_type == RTE_ETHER_TYPE_ARP) {
                    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(
                        bufs[i], struct rte_arp_hdr *,
                        sizeof(struct rte_ether_hdr));

                    if (rte_be_to_cpu_16(arp_hdr->arp_hardware) ==
                            RTE_ARP_HRD_ETHER &&
                        rte_be_to_cpu_16(arp_hdr->arp_protocol) ==
                            RTE_ETHER_TYPE_IPV4) {
                        dst_ip.family = AF_INET;
                        dst_ip.addr.ipv4 = arp_hdr->arp_data.arp_tip;
                    } else {
                        RTE_LOG(DEBUG, LB,
                                "Unsupported ARP packet type, dropping.\n");
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }
                } else {
                    RTE_LOG(DEBUG, LB,
                            "Received non-IP/ARP packet. Dropping packet.\n");
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }

                ret_hash = rte_hash_lookup_data(
                    ip_to_client_table, &dst_ip, (void **)&client_id_ptr);
                if (ret_hash < 0) {
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }
                int client_id = *client_id_ptr;

                uint16_t count = client_buf_counts[client_id];
                client_bufs[client_id][count] = bufs[i];
                client_buf_counts[client_id]++;

                if (client_buf_counts[client_id] == BURST_SIZE) {
                    uint16_t nb_enqueued = rte_ring_enqueue_burst(
                        rx_rings[client_id],
                        (void *const *)client_bufs[client_id], BURST_SIZE,
                        NULL);
                    if (nb_enqueued < BURST_SIZE) {
                        for (uint16_t j = nb_enqueued; j < BURST_SIZE; j++) {
                            rte_pktmbuf_free(client_bufs[client_id][j]);
                        }
                    }
                    client_buf_counts[client_id] = 0;
                }
            }
        }

        /* Flush remaining packets in client buffers */
        for (unsigned i = 0; i < num_clients; i++) {
            if (client_buf_counts[i] > 0) {
                uint16_t nb_enqueued = rte_ring_enqueue_burst(
                    rx_rings[i], (void *const *)client_bufs[i],
                    client_buf_counts[i], NULL);
                if (nb_enqueued < client_buf_counts[i]) {
                    for (uint16_t j = nb_enqueued; j < client_buf_counts[i];
                         j++) {
                        rte_pktmbuf_free(client_bufs[i][j]);
                    }
                }
                client_buf_counts[i] = 0;
            }
        }
		
		/* TX path: Dequeue from rings and send */
        uint16_t nb_to_tx = 0;
        for (unsigned i = 0; i < num_clients; i++) {
            for (;;) {
                uint16_t space_left = BURST_SIZE - nb_to_tx;
                if (space_left == 0) {
                    // Buffer full, send it
                    uint16_t nb_tx = rte_eth_tx_burst(0, queue_id, tx_burst_buffer, nb_to_tx);
                    if (nb_tx < nb_to_tx) {
						RTE_LOG(
							WARNING, LB,
							"Failed to send all packets to NIC. Dropping %u packets.\n",
							nb_to_tx - nb_tx);
                        for (uint16_t j = nb_tx; j < nb_to_tx; j++) {
                            rte_pktmbuf_free(tx_burst_buffer[j]);
                        }
                    }
                    nb_to_tx = 0;
                    continue; // Try to dequeue from the same ring again
                }

                uint16_t nb_dequeued = rte_ring_dequeue_burst(
                    tx_rings[i], (void **)&tx_burst_buffer[nb_to_tx], space_left, NULL);
                
                if (nb_dequeued == 0) {
                    // Ring i is empty, move to next ring
                    break; 
                }
                
                nb_to_tx += nb_dequeued;
            }
        }

        // Send any remaining packets
        if (nb_to_tx > 0) {
            uint16_t nb_tx = rte_eth_tx_burst(0, queue_id, tx_burst_buffer, nb_to_tx);
            if (nb_tx < nb_to_tx) {
				RTE_LOG(
					WARNING, LB,
					"Failed to send all packets to NIC. Dropping %u packets.\n",
					nb_to_tx - nb_tx);
                for (uint16_t j = nb_tx; j < nb_to_tx; j++) {
                    rte_pktmbuf_free(tx_burst_buffer[j]);
                }
            }
        }
    }
    RTE_LOG(INFO, LB, "Lcore %u (RX/TX, queue %u) exiting.\n", lcore_id, queue_id);
	if (l_arg) {
		free(l_arg);
	}
    return 0;
}

static int lcore_rx(void *arg) {
    struct lcore_arg *l_arg = (struct lcore_arg *)arg;
    const uint16_t queue_id = l_arg->queue_id;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *client_bufs[MAX_CLIENTS][BURST_SIZE];
    uint16_t client_buf_counts[MAX_CLIENTS] = {0};

    RTE_LOG(INFO, LB, "Starting RX loop on lcore %u, queue %u for %u clients\n",
            lcore_id, queue_id, num_clients);

    while (!quit_signal) {
        /* RX path: Receive from NIC and distribute to clients */
        uint16_t nb_rx = rte_eth_rx_burst(0, queue_id, bufs, BURST_SIZE);
        if (nb_rx > 0) {
            for (uint16_t i = 0; i < nb_rx; i++) {
                rte_prefetch0(rte_pktmbuf_mtod(bufs[i], void *));

                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                ip_addr_t dst_ip;
                int32_t *client_id_ptr;
                int ret_hash;
                uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

                //memset(&dst_ip, 0, sizeof(ip_addr_t));

                if (eth_type == RTE_ETHER_TYPE_IPV4) {
                    struct rte_ipv4_hdr *ipv4_hdr =
                        rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv4_hdr *,
                                                sizeof(struct rte_ether_hdr));
                    dst_ip.family = AF_INET;
                    dst_ip.addr.ipv4 = ipv4_hdr->dst_addr;
                } else if (eth_type == RTE_ETHER_TYPE_IPV6) {
                    struct rte_ipv6_hdr *ipv6_hdr =
                        rte_pktmbuf_mtod_offset(bufs[i], struct rte_ipv6_hdr *,
                                                sizeof(struct rte_ether_hdr));
                    dst_ip.family = AF_INET6;
                    memcpy(dst_ip.addr.ipv6, ipv6_hdr->dst_addr.a, sizeof(ipv6_hdr->dst_addr.a));
                } else if (eth_type == RTE_ETHER_TYPE_ARP) {
                    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(
                        bufs[i], struct rte_arp_hdr *,
                        sizeof(struct rte_ether_hdr));

                    if (rte_be_to_cpu_16(arp_hdr->arp_hardware) ==
                            RTE_ARP_HRD_ETHER &&
                        rte_be_to_cpu_16(arp_hdr->arp_protocol) ==
                            RTE_ETHER_TYPE_IPV4) {
                        dst_ip.family = AF_INET;
                        dst_ip.addr.ipv4 = arp_hdr->arp_data.arp_tip;
                    } else {
                        RTE_LOG(DEBUG, LB,
                                "Unsupported ARP packet type, dropping.\n");
                        rte_pktmbuf_free(bufs[i]);
                        continue;
                    }
                } else {
                    RTE_LOG(DEBUG, LB,
                            "Received non-IP/ARP packet. Dropping packet.\n");
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }

                ret_hash = rte_hash_lookup_data(
                    ip_to_client_table, &dst_ip, (void **)&client_id_ptr);
                if (ret_hash < 0) {
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }
                int client_id = *client_id_ptr;

                uint16_t count = client_buf_counts[client_id];
                client_bufs[client_id][count] = bufs[i];
                client_buf_counts[client_id]++;

                if (client_buf_counts[client_id] == BURST_SIZE) {
                    uint16_t nb_enqueued = rte_ring_enqueue_burst(
                        rx_rings[client_id],
                        (void *const *)client_bufs[client_id], BURST_SIZE,
                        NULL);
                    if (nb_enqueued < BURST_SIZE) {
                        for (uint16_t j = nb_enqueued; j < BURST_SIZE; j++) {
                            rte_pktmbuf_free(client_bufs[client_id][j]);
                        }
                    }
                    client_buf_counts[client_id] = 0;
                }
            }
        }

        /* Flush remaining packets in client buffers */
        for (unsigned i = 0; i < num_clients; i++) {
            if (client_buf_counts[i] > 0) {
                uint16_t nb_enqueued = rte_ring_enqueue_burst(
                    rx_rings[i], (void *const *)client_bufs[i],
                    client_buf_counts[i], NULL);
                if (nb_enqueued < client_buf_counts[i]) {
                    for (uint16_t j = nb_enqueued; j < client_buf_counts[i];
                         j++) {
                        rte_pktmbuf_free(client_bufs[i][j]);
                    }
                }
                client_buf_counts[i] = 0;
            }
        }
    }
    RTE_LOG(INFO, LB, "Lcore %u (RX, queue %u) exiting.\n", lcore_id, queue_id);
	if (l_arg) {
		free(l_arg);
	}
    return 0;
}

static int lcore_tx(void *arg) {
    struct lcore_arg *l_arg = (struct lcore_arg *)arg;
    const uint16_t queue_id = l_arg->queue_id;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *tx_burst_buffer[BURST_SIZE];

    RTE_LOG(INFO, LB, "Starting TX loop on lcore %u, queue %u for %u clients\n",
            lcore_id, queue_id, num_clients);

    while (!quit_signal) {
		/* TX path: Dequeue from rings and send */
        uint16_t nb_to_tx = 0;
        for (unsigned i = 0; i < num_clients; i++) {
            for (;;) {
                uint16_t space_left = BURST_SIZE - nb_to_tx;
                if (space_left == 0) {
                    // Buffer full, send it
                    uint16_t nb_tx = rte_eth_tx_burst(0, queue_id, tx_burst_buffer, nb_to_tx);
                    if (nb_tx < nb_to_tx) {
						RTE_LOG(
							WARNING, LB,
							"Failed to send all packets to NIC. Dropping %u packets.\n",
							nb_to_tx - nb_tx);
                        for (uint16_t j = nb_tx; j < nb_to_tx; j++) {
                            rte_pktmbuf_free(tx_burst_buffer[j]);
                        }
                    }
                    nb_to_tx = 0;
                    continue; // Try to dequeue from the same ring again
                }

                uint16_t nb_dequeued = rte_ring_dequeue_burst(
                    tx_rings[i], (void **)&tx_burst_buffer[nb_to_tx], space_left, NULL);
                
                if (nb_dequeued == 0) {
                    // Ring i is empty, move to next ring
                    break; 
                }
                
                nb_to_tx += nb_dequeued;
            }
        }

        // Send any remaining packets
        if (nb_to_tx > 0) {
            uint16_t nb_tx = rte_eth_tx_burst(0, queue_id, tx_burst_buffer, nb_to_tx);
            if (nb_tx < nb_to_tx) {
				RTE_LOG(
					WARNING, LB,
					"Failed to send all packets to NIC. Dropping %u packets.\n",
					nb_to_tx - nb_tx);
                for (uint16_t j = nb_tx; j < nb_to_tx; j++) {
                    rte_pktmbuf_free(tx_burst_buffer[j]);
                }
            }
        }
    }
    RTE_LOG(INFO, LB, "Lcore %u (TX, queue %u) exiting.\n", lcore_id, queue_id);
	if (l_arg) {
		free(l_arg);
	}
    return 0;
}


static void cleanup_dpdk_config(void) {
    if (dpdk_config_args != NULL) {
        free(dpdk_config_args);
        dpdk_config_args = NULL;
    }
    for (int i = 0; i < eal_args_count; i++) {
        if (eal_args_array[i] != NULL) {
            free(eal_args_array[i]);
            eal_args_array[i] = NULL;
        }
    }
    eal_args_count = 0;
    if (global_clients_json != NULL) {
        cJSON_Delete(global_clients_json);
        global_clients_json = NULL;
    }
}

static int init_client_hash_table(void) {
    if (global_clients_json == NULL) {
        RTE_LOG(ERR, LB, "Global clients JSON is NULL, cannot initialize hash table.\n");
        return -1;
    }

    struct rte_hash_parameters hash_params = {
        .name = "ip_to_client",
        .entries = IP_HASH_ENTRIES,
        .key_len = sizeof(ip_addr_t),
        .hash_func = ip_addr_hash_func,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
    };
    ip_to_client_table = rte_hash_create(&hash_params);
    if (!ip_to_client_table) {
        RTE_LOG(ERR, LB, "Cannot create hash table\n");
        return -1;
    }

    cJSON *client_item;
    cJSON_ArrayForEach(client_item, global_clients_json) {
        cJSON *id_item = cJSON_GetObjectItemCaseSensitive(client_item, "id");
        cJSON *ips_array = cJSON_GetObjectItemCaseSensitive(client_item, "ips");
        if (!cJSON_IsNumber(id_item) || !cJSON_IsArray(ips_array)) {
            RTE_LOG(WARNING, LB, "Invalid client item in JSON, skipping.\n");
            continue;
        }

        int client_id = id_item->valueint;
        cJSON *ip_item;
        cJSON_ArrayForEach(ip_item, ips_array) {
            if (cJSON_IsString(ip_item) && (ip_item->valuestring != NULL)) {
                ip_addr_t ip_addr;
                memset(&ip_addr, 0, sizeof(ip_addr_t));

                if (inet_pton(AF_INET, ip_item->valuestring, &ip_addr.addr.ipv4) == 1) {
                    ip_addr.family = AF_INET;
                } else if (inet_pton(AF_INET6, ip_item->valuestring, &ip_addr.addr.ipv6) == 1) {
                    ip_addr.family = AF_INET6;
                } else {
                    RTE_LOG(ERR, LB, "Invalid IP address format: %s\n",
                            ip_item->valuestring);
                    continue;
                }

                int *id_ptr = malloc(sizeof(int));
                if (!id_ptr) {
                    RTE_LOG(ERR, LB, "Failed to allocate memory for client_id\n");
                    continue;
                }
                *id_ptr = client_id;
                if (rte_hash_add_key_data(ip_to_client_table, &ip_addr,
                                          (void *)id_ptr) < 0) {
                    RTE_LOG(ERR, LB, "Failed to add IP %s to hash table\n",
                            ip_item->valuestring);
                    free(id_ptr);
                }
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *config_file_path = argv[1];
    // struct rte_mempool *mbuf_pool; // Removed local declaration
    unsigned nb_ports;
    uint16_t portid = 0;
    int ret;
    // unsigned lcore_id; // Removed unused variable

    /* Register signal handler for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    atexit(cleanup_dpdk_config); // Register cleanup function

    if (parse_full_config(config_file_path) < 0)
        rte_panic("Failed to parse full config");

    // Construct argv for rte_eal_init
    int eal_init_argc;
    char **eal_init_argv;

    if (eal_args_count > 0) {
        eal_init_argc = eal_args_count + 1; // +1 for program name
        eal_init_argv = calloc(eal_init_argc + 1, sizeof(char *)); // +1 for NULL terminator
        if (eal_init_argv == NULL) {
            rte_panic("Failed to allocate memory for eal_init_argv\n");
        }
        eal_init_argv[0] = argv[0]; // Program name
        for (int i = 0; i < eal_args_count; i++) {
            eal_init_argv[i + 1] = eal_args_array[i];
        }
        eal_init_argv[eal_init_argc] = NULL;

        ret = rte_eal_init(eal_init_argc, eal_init_argv);
        free(eal_init_argv);

    } else {
        ret = rte_eal_init(argc, argv);
    }
    
    if (ret < 0) {
        rte_panic("Cannot init EAL\n");
    }
    
	const struct rte_memzone *mz;
    struct lb_shared_info *shared_info;

    mz = rte_memzone_reserve(LB_SHARED_MEMZONE, sizeof(struct lb_shared_info),
                             rte_socket_id(), 0);
    if (mz == NULL) {
        rte_panic("Cannot reserve memzone for shared info\n");
    }
    shared_info = (struct lb_shared_info *)mz->addr;


    if (init_client_hash_table() < 0)
        rte_panic("Failed to initialize client hash table");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
        rte_panic("No Ethernet ports found\n");


    unsigned num_mbufs = (8 * (RING_SIZE + RING_SIZE)) + (num_clients * MBUFS_PER_WORKER);
    int i = 0;
    while (num_mbufs) {
        i++;
        num_mbufs >>= 1;
    }

    num_mbufs = (1 << i) - 1;

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", num_mbufs, MBUF_CACHE_SIZE, 0,
        JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_panic("Cannot create mbuf pool\n");

    for (unsigned i = 0; i < num_clients; i++) {
        char ring_name[64];
        snprintf(ring_name, sizeof(ring_name), RX_RING_NAME_TEMPLATE, i);
        rx_rings[i] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (rx_rings[i] == NULL)
            rte_panic("Cannot create RX ring %u\n", i);
        snprintf(ring_name, sizeof(ring_name), TX_RING_NAME_TEMPLATE, i);
        tx_rings[i] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                                      RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (tx_rings[i] == NULL)
            rte_panic("Cannot create TX ring %u\n", i);
    }

    if (port_init(portid, mbuf_pool, shared_info) != 0)
        rte_panic("Cannot init port %u\n", portid);
    RTE_LOG(INFO, LB, "Finished EAL and port initialization\n");

    unsigned core1_id = lb_core_id;

    // The main lcore from EAL should be our first core.
    if (rte_lcore_id() != core1_id) {
        rte_panic("Main lcore (%u) is not the configured core_id (%u).\n", rte_lcore_id(), core1_id);
    }
    
    if (num_clients < NUMBER_CLIENT_PER_CORE) {
        struct lcore_arg *arg_rxtx = malloc(sizeof(struct lcore_arg));
        if (!arg_rxtx) {
            rte_panic("cannot allocate memory for lcore arg\n");
        }
        arg_rxtx->queue_id = 0;
        RTE_LOG(INFO, LB, "Starting RX/TX on main lcore %u (queue 0)...\n", core1_id);
        lcore_rxtx(arg_rxtx); // This will block until quit_signal
    } else {
        unsigned core2_id = lb_core_id + 1;
        // Check if the second core is enabled and is a worker core.
        if (!rte_lcore_is_enabled(core2_id) || core2_id == rte_get_main_lcore()) {
            rte_panic("Second core %u is not an enabled worker lcore.\n", core2_id);
        }

        struct lcore_arg *arg_tx = malloc(sizeof(struct lcore_arg));
        if (!arg_tx) {
            rte_panic("cannot allocate memory for lcore arg2\n");
        }
        arg_tx->queue_id = 0;

        RTE_LOG(INFO, LB, "Launching TX on worker lcore %u (queue 0)...\n", core2_id);
        if (rte_eal_remote_launch(lcore_tx, arg_tx, core2_id) != 0) {
            free(arg_tx);
            rte_panic("Failed to launch TX on lcore %u.", core2_id);
        }

        struct lcore_arg *arg_rx = malloc(sizeof(struct lcore_arg));
        if (!arg_rx) {
            rte_panic("cannot allocate memory for lcore arg1\n");
        }
        arg_rx->queue_id = 0;
        RTE_LOG(INFO, LB, "Starting RX on main lcore %u (queue 0)...\n", core1_id);
        lcore_rx(arg_rx); // This will block until quit_signal

        rte_eal_wait_lcore(core2_id);
    }


    RTE_LOG(INFO, LB, "All lcores have finished. Exiting.\n");

    RTE_LOG(INFO, LB, "Stopping port %u...\n", portid);
    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);

    return 0;
}

static int parse_full_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        RTE_LOG(ERR, LB, "Cannot open config file %s\n", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buffer = malloc(length + 1);
    if (!buffer) {
        RTE_LOG(ERR, LB, "Cannot allocate memory for config file\n");
        fclose(f);
        return -1;
    }
    if (fread(buffer, 1, length, f) != length) {
        RTE_LOG(ERR, LB, "Failed to read entire config file %s\n", path);
        free(buffer);
        fclose(f);
        return -1;
    }
    fclose(f);
    buffer[length] = '\0';

    RTE_LOG(INFO, LB, "DEBUG: Config file length: %ld\n", length);
    RTE_LOG(INFO, LB, "DEBUG: First 100 chars of buffer: %.*s\n", (length > 100 ? 100 : (int)length), buffer);

    cJSON *json = cJSON_Parse(buffer);
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            RTE_LOG(ERR, LB, "Error parsing JSON: %s\n", error_ptr);
            // Print a snippet of the buffer around the error_ptr for more context
            int offset = error_ptr - buffer;
            int start = offset - 20 < 0 ? 0 : offset - 20;
            int end = offset + 50 > length ? (int)length : offset + 50;
            RTE_LOG(ERR, LB, "Error occurred near: '%.*s'\n", end - start, buffer + start);
        } else {
            RTE_LOG(ERR, LB, "Error parsing JSON (unknown reason)\n");
        }
        free(buffer);
        return -1;
    }

    cJSON *core_id_item = cJSON_GetObjectItemCaseSensitive(json, "core_id");
    if (cJSON_IsNumber(core_id_item)) {
        lb_core_id = core_id_item->valueint;
    } else {
        RTE_LOG(WARNING, LB, "No 'core_id' found in config or it's not a number. Using default core_id 0.\n");
        lb_core_id = 0; // Default value
    }

    // Parse num_clients
    cJSON *num_clients_item =
        cJSON_GetObjectItemCaseSensitive(json, "num_clients");
    if (!cJSON_IsNumber(num_clients_item) || num_clients_item->valueint <= 0 ||
        num_clients_item->valueint > MAX_CLIENTS) {
        RTE_LOG(ERR, LB, "Invalid 'num_clients' in config\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }
    num_clients = num_clients_item->valueint;

    cJSON *dpdk_args_item = cJSON_GetObjectItemCaseSensitive(json, "dpdk_args");
    char *raw_dpdk_args = NULL;
    if (cJSON_IsString(dpdk_args_item) && (dpdk_args_item->valuestring != NULL)) {
        raw_dpdk_args = dpdk_args_item->valuestring;
    } else {
        RTE_LOG(WARNING, LB, "No 'dpdk_args' found in config or it's not a string.\n");
        raw_dpdk_args = ""; // Use empty string if no args specified
    }

    // Construct the full DPDK args string
    int tx_core_id = lb_core_id + 1;
	int needed_len;
    if (num_clients < NUMBER_CLIENT_PER_CORE) {
        needed_len = snprintf(NULL, 0, "-l%d %s", lb_core_id, raw_dpdk_args) + 1;
    } else {
        needed_len = snprintf(NULL, 0, "-l%d-%d %s", lb_core_id, tx_core_id, raw_dpdk_args) + 1;
    }
    dpdk_config_args = malloc(needed_len);
    if (dpdk_config_args == NULL) {
        RTE_LOG(ERR, LB, "Failed to allocate memory for dpdk_config_args\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }
    if (num_clients < NUMBER_CLIENT_PER_CORE) {
        snprintf(dpdk_config_args, needed_len, "-l%d %s", lb_core_id, raw_dpdk_args);
    } else {
        snprintf(dpdk_config_args, needed_len, "-l%d-%d %s", lb_core_id, tx_core_id, raw_dpdk_args);
    }

    // Now tokenize dpdk_config_args
    char *s = strdup(dpdk_config_args); // strdup because strtok_r modifies the string
    if (s == NULL) {
        RTE_LOG(ERR, LB, "Failed to duplicate dpdk_config_args for tokenizing\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }

    char *token;
    char *rest = s;
    eal_args_count = 0;
    while ((token = strtok_r(rest, " ", &rest)) && (eal_args_count < MAX_EAL_ARGS)) {
        eal_args_array[eal_args_count++] = strdup(token);
        if (eal_args_array[eal_args_count - 1] == NULL) {
            RTE_LOG(ERR, LB, "Failed to duplicate EAL argument token\n");
            for (int i = 0; i < eal_args_count - 1; i++) {
                free(eal_args_array[i]);
            }
            free(s);
            cJSON_Delete(json);
            free(buffer);
            return -1;
        }
    }
    free(s);

    if (eal_args_count == MAX_EAL_ARGS) {
        RTE_LOG(WARNING, LB, "Truncated DPDK EAL arguments due to MAX_EAL_ARGS limit.\n");
    }

    // Store clients array for later processing
    cJSON *clients_array_item = cJSON_GetObjectItemCaseSensitive(json, "clients");
    if (!cJSON_IsArray(clients_array_item)) {
        RTE_LOG(ERR, LB, "Clients array not found or invalid\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }
    
    // Deep copy the clients_array to a global cJSON object for later use
    global_clients_json = cJSON_Duplicate(clients_array_item, 1);
    if (global_clients_json == NULL) {
        RTE_LOG(ERR, LB, "Failed to duplicate clients JSON array\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }


    cJSON_Delete(json);
    free(buffer);
    return 0;
}
