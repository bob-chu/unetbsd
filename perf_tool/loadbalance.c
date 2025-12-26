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

#include "cJSON.h"
#include "common.h"

struct lcore_args {
    uint16_t queue_id;
};

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
#define RING_SIZE (1024 * 4)
#define IP_HASH_ENTRIES 1024
#define MAX_EAL_ARGS 64 // Max number of DPDK EAL arguments


#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS (8191 * 8)
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64 
#define JUMBO_FRAME_MAX_SIZE 9600

static uint16_t nb_rx_queues = 1;
static uint16_t nb_tx_queues = 1;

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

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));
    port_conf.rxmode.mq_mode =
        RTE_ETH_MQ_RX_NONE; // No RSS when handling traffic to specific clients

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        RTE_LOG(ERR, LB, "Error getting device (port %u) info: %s\n", port,
                strerror(-retval));
        return retval;
    }
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    retval =
        rte_eth_dev_configure(port, nb_rx_queues, nb_tx_queues, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    for (q = 0; q < nb_rx_queues; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < nb_tx_queues; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

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



static int lcore_rx(void *arg) {
    struct lcore_args *my_args = (struct lcore_args *)arg;
    const uint16_t queue_id = my_args->queue_id;
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
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
                ip_addr_t dst_ip;
                int32_t *client_id_ptr;
                int ret_hash;
                uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

                memset(&dst_ip, 0, sizeof(ip_addr_t));

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
                    printf("No client found for destination IP. Dropping "
                            "packet.\n");
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
                    ;//printf("Send %d pkts to client: %d\n", nb_enqueued, client_id);
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
                ;//printf("Send %d pkts to client: %d\n", nb_enqueued, i);
                client_buf_counts[i] = 0;
            }
        }
    }
    RTE_LOG(INFO, LB, "Lcore %u (RX) exiting.\n", lcore_id);
    return 0;
}

static int lcore_tx(void *arg) {
    struct lcore_args *my_args = (struct lcore_args *)arg;
    const uint16_t queue_id = my_args->queue_id;
    const unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *tx_burst_buffer[BURST_SIZE];

    RTE_LOG(INFO, LB, "Starting TX loop on lcore %u, queue %u for %u clients\n",
            lcore_id, queue_id, num_clients);

    while (!quit_signal) {
        /* TX path: Aggregate packets from all clients into a single burst */
        uint16_t nb_to_tx = 0;
        for (unsigned i = 0; i < num_clients; i++) {
            uint16_t space_left = BURST_SIZE - nb_to_tx;
            if (space_left == 0)
                break;
            uint16_t nb_dequeued = rte_ring_dequeue_burst(
                tx_rings[i], (void **)&tx_burst_buffer[nb_to_tx], space_left,
                NULL);
            nb_to_tx += nb_dequeued;
        }

        if (nb_to_tx > 0) {
            uint16_t nb_tx =
                rte_eth_tx_burst(0, queue_id, tx_burst_buffer, nb_to_tx);
            if (nb_tx < nb_to_tx) {
                RTE_LOG(
                    WARNING, LB,
                    "Failed to send all packets to NIC. Dropping %u packets.\n",
                    nb_to_tx - nb_tx);
                for (uint16_t j = nb_tx; j < nb_to_tx; j++) {
                    rte_pktmbuf_free(tx_burst_buffer[j]);
                }
            } else {
                ;//printf("Send out %d pkts\n", nb_tx);
            }
        }
    }
    RTE_LOG(INFO, LB, "Lcore %u (TX) exiting.\n", lcore_id);
    return 0;
}

static char* generate_lcores_arg(int base_core_id, int num_cores) {
    if (num_cores <= 0) {
        return strdup("");
    }

    // Estimate buffer size: each entry "L@P," is about 5-8 chars, plus "--lcores ", and null terminator
    // Max cores is probably 64, so 64 * 8 + 10 = ~522 chars
    size_t buffer_size = 10; // For "--lcores "
    // Add space for each core mapping: "L@P,"
    // Assuming L and P are up to 2 digits, "00@00," is 6 chars. num_cores * 6 + num_cores -1 for commas
    buffer_size += num_cores * 8; // A bit generous to account for larger core IDs and safety

    char *lcores_str = malloc(buffer_size);
    if (lcores_str == NULL) {
        return NULL; // Allocation failed
    }
    
    int offset = snprintf(lcores_str, buffer_size, "--lcores ");
    if (offset < 0 || (size_t)offset >= buffer_size) {
        free(lcores_str);
        return NULL;
    }

    for (int i = 0; i < num_cores; ++i) {
        offset += snprintf(lcores_str + offset, buffer_size - offset, "%d@%d%s",
                           i, base_core_id + i, (i == num_cores - 1) ? "" : ",");
        if (offset < 0 || (size_t)offset >= buffer_size) {
            free(lcores_str);
            return NULL; // Error or buffer too small
        }
    }
    return lcores_str;
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

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
        JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_panic("Cannot create mbuf pool\n");

    for (unsigned i = 0; i < num_clients; i++) {
        char ring_name[32];
        snprintf(ring_name, sizeof(ring_name), RX_RING_NAME_TEMPLATE, i);
        rx_rings[i] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                                      0);
        if (rx_rings[i] == NULL)
            rte_panic("Cannot create RX ring %u\n", i);
        snprintf(ring_name, sizeof(ring_name), TX_RING_NAME_TEMPLATE, i);
        tx_rings[i] = rte_ring_create(ring_name, RING_SIZE, rte_socket_id(),
                                      0);
        if (tx_rings[i] == NULL)
            rte_panic("Cannot create TX ring %u\n", i);
    }

    if (port_init(portid, mbuf_pool, shared_info) != 0)
        rte_panic("Cannot init port %u\n", portid);
    RTE_LOG(INFO, LB, "Finished EAL and port initialization\n");

    // Ensure the main lcore is the configured lb_core_id
    if (rte_lcore_id() != lb_core_id) {
        rte_panic("Main lcore (%u) is not the configured lb_core_id (%u). "
                  "Please ensure the EAL arguments configure the main lcore "
                  "correctly (e.g., -l%u).",
                  rte_lcore_id(), lb_core_id, lb_core_id);
    }

    unsigned lcores_to_launch = (nb_rx_queues - 1) + nb_tx_queues;
    if (lcores_to_launch > 0) { // Only if worker cores are needed
        unsigned int lcore_id_iter;
        unsigned int worker_lcore_count = 0;
        RTE_LCORE_FOREACH_WORKER(lcore_id_iter) {
            worker_lcore_count++;
        }

        if (worker_lcore_count < lcores_to_launch) {
            rte_panic("Not enough enabled worker lcores. "
                      "Needed %u, but found only %u enabled worker lcores. "
                      "Please adjust EAL core mask (-l option).",
                      lcores_to_launch, worker_lcore_count);
        }
    }

    struct lcore_args *args[nb_rx_queues + nb_tx_queues];
    int arg_idx = 0;
    unsigned int current_worker_lcore_id;

    // Launch additional RX threads (if any) on worker lcores
    current_worker_lcore_id = rte_get_next_lcore(rte_get_main_lcore(), 1, 0); // Start from first worker lcore
    for (uint16_t i = 1; i < nb_rx_queues; i++) {
        if (current_worker_lcore_id == RTE_MAX_LCORE) {
            rte_panic("Not enough enabled worker lcores to launch RX queue %u. "
                      "This should have been caught by an earlier check.", i);
        }
        
        args[arg_idx] = malloc(sizeof(struct lcore_args));
        if (args[arg_idx] == NULL) {
            rte_panic("Failed to allocate memory for lcore_args.\n");
        }
        args[arg_idx]->queue_id = i;
        RTE_LOG(INFO, LB, "Launching RX on worker lcore %u, queue %u...\n", current_worker_lcore_id, i);
        if (rte_eal_remote_launch(lcore_rx, args[arg_idx], current_worker_lcore_id) != 0) {
            rte_panic("Failed to launch RX on lcore %u.", current_worker_lcore_id);
        }
        arg_idx++;
        current_worker_lcore_id = rte_get_next_lcore(current_worker_lcore_id, 1, 0); // Get next worker lcore
    }

    // Launch TX threads on worker lcores
    for (uint16_t i = 0; i < nb_tx_queues; i++) {
        if (current_worker_lcore_id == RTE_MAX_LCORE) {
            rte_panic("Not enough enabled worker lcores to launch TX queue %u. "
                      "This should have been caught by an earlier check.", i);
        }

        args[arg_idx] = malloc(sizeof(struct lcore_args));
        if (args[arg_idx] == NULL) {
            rte_panic("Failed to allocate memory for lcore_args.\n");
        }
        args[arg_idx]->queue_id = i;
        RTE_LOG(INFO, LB, "Launching TX on worker lcore %u, queue %u...\n", current_worker_lcore_id, i);
        if (rte_eal_remote_launch(lcore_tx, args[arg_idx], current_worker_lcore_id) != 0) {
            rte_panic("Failed to launch TX on lcore %u.", current_worker_lcore_id);
        }
        arg_idx++;
        current_worker_lcore_id = rte_get_next_lcore(current_worker_lcore_id, 1, 0); // Get next worker lcore
    }

    // Start RX on the main lcore (queue 0)
    args[arg_idx] = malloc(sizeof(struct lcore_args));
    if (args[arg_idx] == NULL) {
        rte_panic("Failed to allocate memory for lcore_args.\n");
    }
    args[arg_idx]->queue_id = 0;
    RTE_LOG(INFO, LB, "Starting RX on main lcore %u, queue 0...\n", rte_lcore_id());
    lcore_rx(args[arg_idx]); // This will block until quit_signal
    arg_idx++;

    // Wait for all worker lcores to finish
    unsigned lcore_id_wait;
    RTE_LCORE_FOREACH_WORKER(lcore_id_wait) {
        rte_eal_wait_lcore(lcore_id_wait);
    }

    RTE_LOG(INFO, LB, "All lcores have finished. Exiting.\n");

    for (int i = 0; i < arg_idx; i++) {
        free(args[i]);
    }


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

    cJSON *dpdk_args_item = cJSON_GetObjectItemCaseSensitive(json, "dpdk_args");
    char *raw_dpdk_args = NULL;
    if (cJSON_IsString(dpdk_args_item) && (dpdk_args_item->valuestring != NULL)) {
        raw_dpdk_args = dpdk_args_item->valuestring;
    } else {
        RTE_LOG(WARNING, LB, "No 'dpdk_args' found in config or it's not a string.\n");
        raw_dpdk_args = ""; // Use empty string if no args specified
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

    if (num_clients > 32) {
        nb_rx_queues = 2;
        nb_tx_queues = 2;
    }

    // Construct the full DPDK args string
    // Allocate enough memory for the generated --lcores string + raw_dpdk_args + null terminator
    int num_needed_cores = nb_rx_queues + nb_tx_queues;
    char *lcores_generated_arg = generate_lcores_arg(lb_core_id, num_needed_cores);
    if (lcores_generated_arg == NULL) {
        RTE_LOG(ERR, LB, "Failed to generate --lcores argument string\n");
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }

    int needed_len = snprintf(NULL, 0, "%s %s", lcores_generated_arg, raw_dpdk_args) + 1;
    dpdk_config_args = malloc(needed_len);
    if (dpdk_config_args == NULL) {
        RTE_LOG(ERR, LB, "Failed to allocate memory for dpdk_config_args\n");
        free(lcores_generated_arg); // Free the generated arg string
        cJSON_Delete(json);
        free(buffer);
        return -1;
    }
    snprintf(dpdk_config_args, needed_len, "%s %s", lcores_generated_arg, raw_dpdk_args);
    free(lcores_generated_arg); // Free the generated arg string after copying

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


