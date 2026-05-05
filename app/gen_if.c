#include "string.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_vhost.h>

#include <stdbool.h>

#include "u_if.h"
#include "gen_if.h"
#include "logger.h"


#define MAX_PKT_BURST 64
#define RX_RING_SIZE 128
#define TX_RING_SIZE 128
#define CLIENT_QUEUE_RINGSIZE 1024

//#define NUM_MBUFS 8191
#define NUM_MBUFS 1024
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE 32
#define PORT_QUEUE_SZ 1
#define JUMBO_FRAME_MAX_SIZE 9600 // Support for jumbo frames up to 9600 bytes

// Exported for shim integration
struct virt_interface *v_f_dpdk;
struct rte_ether_addr dpdk_port_addr;
// Define symmetric RSS key - exactly 40 bytes for MLX5
static uint8_t symmetric_rsskey[40] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a
};

struct rte_mempool *mbuf_pool;
unsigned nb_ports;
uint16_t portid;
static uint16_t tx_pkts;
static struct rte_eth_dev_tx_buffer *tx_buffer;
static uint8_t num_queue;
static struct client_ring *client_rings;
static struct client_ring curr_client_ring;

int nb_procs = 1;
int proc_id = 0;

struct client_rx_buf {
	struct rte_mbuf *buffer[BURST_SIZE];
	uint16_t count;
};

struct rte_ring *shadow_arp_ring = NULL;

static inline char *get_arp_ring_name(int id) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "ARP_RING_%d", id);
    return buf;
}

/* One buffer per client rx queue - dynamically allocate array */
static struct client_rx_buf *cl_rx_buf;

lb_func_t gl_lb_callback;

static inline char *get_mbuf_pool_name(int id);

void register_lb_callback(lb_func_t lb_callback)
{
    gl_lb_callback = lb_callback;
}

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *p_mbuf_pool)
{
    uint16_t rx_rings = PORT_QUEUE_SZ, tx_rings = PORT_QUEUE_SZ;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_txconf txconf;
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;

    if (nb_procs > 1) {
        rx_rings = tx_rings = nb_procs;
    }

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        LOG_INFO("Error getting device (port %u) info: %s\n", port,
                strerror(-retval));
        return retval;
    }

    if (rx_rings > dev_info.max_rx_queues) rx_rings = dev_info.max_rx_queues;
    if (tx_rings > dev_info.max_tx_queues) tx_rings = dev_info.max_tx_queues;

    LOG_INFO("Initializing port with %u RX queues and %u TX queues (Max: %u/%u)", 
            rx_rings, tx_rings, dev_info.max_rx_queues, dev_info.max_tx_queues);

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    uint64_t rss_hf_temp = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP;
    port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf_temp & dev_info.flow_type_rss_offloads;

    if (port_conf.rx_adv_conf.rss_conf.rss_hf != 0) {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS; // Enable RSS only if hash functions are supported
        port_conf.rx_adv_conf.rss_conf.rss_key = symmetric_rsskey;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
        LOG_INFO("Port %u: Enabled RSS with hash functions: 0x%" PRIx64 "\n", port, port_conf.rx_adv_conf.rss_conf.rss_hf);
    } else {
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE; // No RSS if no hash functions are supported
        LOG_INFO("Port %u: No supported RSS hash functions found. Disabling RSS.\n", port);
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TCP_CKSUM;

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

    // Set MTU for jumbo frames
    uint16_t mtu = JUMBO_FRAME_MAX_SIZE - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN;
    retval = rte_eth_dev_set_mtu(port, mtu);
    if (retval != 0) {
        LOG_INFO("Port %u: Failed to set MTU to %u: %s (Continuing with default MTU)\n", port, mtu, strerror(-retval));
        // Do not return error, proceed with default MTU
    }

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        struct rte_mempool *q_pool;
        if (nb_procs <= 1 || q == 0) q_pool = p_mbuf_pool;
        else q_pool = rte_mempool_lookup(get_mbuf_pool_name(q));
        
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, q_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Configure RETA if RSS is enabled and multiple processes */
    if (nb_procs > 1 && port_conf.rxmode.mq_mode == RTE_ETH_MQ_RX_RSS) {
        struct rte_eth_rss_reta_entry64 reta_conf[2]; // 128 entries
        memset(reta_conf, 0, sizeof(reta_conf));
        for (int i = 0; i < 128; i++) {
            reta_conf[i / 64].mask |= (1ULL << (i % 64));
            reta_conf[i / 64].reta[i % 64] = i % nb_procs;
        }
        retval = rte_eth_dev_rss_reta_update(port, reta_conf, 128);
        if (retval != 0) {
            LOG_INFO("Port %u: Failed to update RETA: %s\n", port, strerror(-retval));
        } else {
            LOG_INFO("Port %u: Updated RETA for %d queues\n", port, nb_procs);
        }
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(0, &dpdk_port_addr);
    if (retval != 0)
        return retval;

    LOG_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port, RTE_ETHER_ADDR_BYTES(&dpdk_port_addr));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

void dump_mbuf_hex(struct rte_mbuf *mbuf, char *msg)
{
    return;

    if (!mbuf) {
        LOG_INFO("Invalid mbuf\n");
        return;
    }

    // Get the pointer to the data and the data length
    const uint8_t *data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    uint16_t data_len = rte_pktmbuf_data_len(mbuf);

    LOG_DEBUG("Mbuf data dump: %s (length=%u):", msg, data_len);

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

// Wait for link to come up (important for memif where handshake happens asynchronously)
int dpdk_wait_link_up(int timeout_ms)
{
    struct rte_eth_link link;
    int elapsed = 0;
    const int poll_interval = 10; // ms
    
    while (elapsed < timeout_ms) {
        rte_eth_link_get_nowait(0, &link);
        if (link.link_status == RTE_ETH_LINK_UP) {
            LOG_INFO("Link UP after %d ms, speed=%u Mbps", elapsed, link.link_speed);
            return 0;
        }
        rte_delay_ms(poll_interval);
        elapsed += poll_interval;
    }
    LOG_INFO("Link UP timeout after %d ms (link_status=%d)", timeout_ms, link.link_status);
    return -1; // timeout, but we can still proceed
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    dump_mbuf_hex(m, "OUT");
    rte_eth_tx_buffer(0, proc_id, tx_buffer, m);

    return 0;
}

int
gen_if_output(void *m, long unsigned int total, void *arg)
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

    struct rte_mbuf *buf = rte_pktmbuf_alloc(mbuf_pool);
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

    /* Handover to DPDK without offload flags (Checksum is now in payload) */
    buf->ol_flags = 0;
    return send_single_packet(buf, 0);

out:
    return 0;
}

void single_mbuf_input(struct rte_mbuf *pkt)
{
    dump_mbuf_hex(pkt, "IN");
    /* Original copy path */
    void *data = rte_pktmbuf_mtod(pkt, void*);
    uint16_t len = rte_pktmbuf_data_len(pkt);
    void *hdr = netbsd_mget_hdr(data, len);
    if (hdr == NULL) {
        rte_pktmbuf_free(pkt);
        return;
    }
    struct rte_mbuf *pn = pkt->next;
    void *prev = hdr;
    bool flag = true;
    while(pn != NULL) {
        data = rte_pktmbuf_mtod(pn, void*);
        len = rte_pktmbuf_data_len(pn);

        void *mb = netbsd_mget_data(prev, data, len);
        if (mb == NULL) {
            netbsd_freembuf(hdr);
            flag = false;
            break;
        }

        prev = mb;
        pn = pn->next;
    }

    if (flag) {
        /* NetBSD stack will verify checksums in software since if_csum_flags_rx is 0 */
        netbsd_mbuf_set_csum_flags(hdr, 0);
        
        virt_if_mbuf_input(v_f_dpdk, hdr);
    }

    rte_pktmbuf_free(pkt);
}


static int is_arp_packet(struct rte_mbuf *pkt)
{
    // Get the Ethernet header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    // Check if the Ethernet type is ARP (0x0806)
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
        return 1;  // This is an ARP packet
    }

    return 0;  // Not an ARP packet
}

static void get_ports(struct rte_mbuf *pkt, int *prot, uint16_t *src_port, uint16_t *dst_port)
{
    // Get Ethernet header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);

    // Check if it's an IP packet
    if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
        return;  // Not an IPv4 packet
    }

    // Get IP header
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    // Check transport layer protocol
    switch (ip_hdr->next_proto_id) {
        case IPPROTO_TCP: {
                              // TCP header follows IP header
                              struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);

                              *src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
                              *dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
                              *prot = IPPROTO_TCP;
                          }
                          break;
        case IPPROTO_UDP: {
                              // UDP header follows IP header
                              struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);

                              *src_port = rte_be_to_cpu_16(udp_hdr->src_port);
                              *dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
                              *prot = IPPROTO_UDP;
                          }
                          break;
        default:
                          break; // Not TCP or UDP
    }
}


/*
 * send a burst of traffic to a client, assuming there are packets
 * available to be sent to this client
 */
static void
flush_rx_queue(uint16_t client)
{
	uint16_t j;
	struct client_ring *cl;

	if (cl_rx_buf[client].count == 0)
		return;

	cl = &client_rings[client];
	if (rte_ring_enqueue_bulk(cl->rx_q, (void **)cl_rx_buf[client].buffer,
			cl_rx_buf[client].count, NULL) == 0){
		for (j = 0; j < cl_rx_buf[client].count; j++)
			rte_pktmbuf_free(cl_rx_buf[client].buffer[j]);
		cl->stats.rx_drop += cl_rx_buf[client].count;
	}
	else
		cl->stats.rx += cl_rx_buf[client].count;

	cl_rx_buf[client].count = 0;
}

static inline void
enqueue_rx_packet(uint8_t client, struct rte_mbuf *buf)
{
    //LOG_DEBUG("send packet to rx_queue [%u]", client);
    cl_rx_buf[client].buffer[cl_rx_buf[client].count++] = buf;
    if (cl_rx_buf[client].count > (BURST_SIZE-2)) {
        flush_rx_queue(client);
    }
}

#include <rte_thash.h>

void port_read(uint8_t queue_id)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(0,
            queue_id,
            bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
       return;

    for (int i = 0; i < nb_rx; i++) {
        struct rte_mbuf *pkt = bufs[i];
        rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
        if (is_arp_packet(pkt)) {
            for (int j = 0; j < nb_procs; j++) {
                if (j != proc_id) {
                    struct rte_mbuf * cloned_pkt = rte_pktmbuf_clone(pkt, mbuf_pool);
                    if (cloned_pkt) {
                        struct rte_ring *r = rte_ring_lookup(get_arp_ring_name(j));
                        if (r) {
                            if (rte_ring_enqueue(r, cloned_pkt) < 0) rte_pktmbuf_free(cloned_pkt);
                        } else {
                            rte_pktmbuf_free(cloned_pkt);
                        }
                    }
                }
            }
        }

        // Process packet directly if RSS is enabled, otherwise use LB or Software RSS
        if (nb_procs > 1 && !gl_lb_callback) {
            // Software RSS fallback
            int prot = 0;
            uint16_t src_port = 0, dst_port = 0;
            uint32_t src_ip = 0, dst_ip = 0;
            
            // Extract L3/L4 info for hashing
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
                struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                src_ip = ipv4_hdr->src_addr;
                dst_ip = ipv4_hdr->dst_addr;
                if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
                    src_port = tcp_hdr->src_port;
                    dst_port = tcp_hdr->dst_port;
                } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
                    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
                    src_port = udp_hdr->src_port;
                    dst_port = udp_hdr->dst_port;
                }
            }

            if (src_port != 0) {
                union rte_thash_tuple tuple;
                tuple.v4.src_addr = src_ip;
                tuple.v4.dst_addr = dst_ip;
                tuple.v4.sport = src_port;
                tuple.v4.dport = dst_port;
                uint32_t hash = rte_softrss_be((uint32_t *)&tuple, RTE_THASH_V4_L4_LEN, symmetric_rsskey);
                uint16_t target_q = hash % nb_procs;
                if (target_q == proc_id) {
                    single_mbuf_input(pkt);
                } else {
                    enqueue_rx_packet(target_q, pkt);
                }
            } else {
                single_mbuf_input(pkt);
            }
        } else if (gl_lb_callback) {
            int prot = 0;
            uint16_t src_port = 0, dst_port = 0;
            get_ports(pkt, &prot, &src_port, &dst_port);
            uint16_t q_id = gl_lb_callback(prot, src_port, dst_port);
            enqueue_rx_packet(q_id, pkt);
        } else {
            enqueue_rx_packet(0, pkt);
        }
    }
    for (uint16_t i = 0; i < nb_procs; i++) {
        flush_rx_queue(i);
    }
}

static void rx_ring_read()
{
    /* dequeue rx_ring */
    uint16_t i, rx_pkts;
    void *pkts[BURST_SIZE];

    rx_pkts = rte_ring_dequeue_burst(client_rings[proc_id].rx_q,
            pkts, BURST_SIZE, NULL);
    if (unlikely(rx_pkts == 0)) return;

    for (i = 0; i < rx_pkts; i++) {
        struct rte_mbuf *buf = (struct rte_mbuf *)pkts[i];
        single_mbuf_input(buf);
    }
}

void dpdk_read()
{
    rte_eth_tx_buffer_flush(0, proc_id, tx_buffer);

    // 1. Process shadow ARP ring
    if (shadow_arp_ring) {
        struct rte_mbuf *arp_bufs[BURST_SIZE];
        int nb_arp = rte_ring_dequeue_burst(shadow_arp_ring, (void **)arp_bufs, BURST_SIZE, NULL);
        for (int i = 0; i < nb_arp; i++) {
            single_mbuf_input(arp_bufs[i]);
        }
    }

    // Only read from port if this process owns a valid hardware queue
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(0, &dev_info);
    if (proc_id < dev_info.max_rx_queues) {
        port_read(proc_id);
    }
    
    rx_ring_read();
}

static void
configure_tx_buffer(uint16_t port_id, uint16_t size)
{
    int ret;
    /* Initialize TX buffers */
    tx_buffer = rte_zmalloc_socket("tx_buffer",
            RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
            rte_eth_dev_socket_id(portid));
    if (tx_buffer == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                (unsigned) portid);

    rte_eth_tx_buffer_init(tx_buffer, size);
}

static int
init_shm_rings(enum rte_proc_type_t proc_type)
{
    unsigned i;
    unsigned socket_id;
    const char * q_name;
    const unsigned ringsize = CLIENT_QUEUE_RINGSIZE;
    unsigned int num_clients = nb_procs;

    /* rx packet buffer */
    cl_rx_buf = calloc(num_clients, sizeof(cl_rx_buf[0]));

    client_rings = rte_malloc("client details",
            sizeof(*client_rings) * num_clients, 0);
    if (client_rings == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate memory for client program details\n");

    for (i = 0; i < num_clients; i++) {
        /* Create an RX queue for each client */
        socket_id = rte_socket_id();
        q_name = get_rx_queue_name(i);
        client_rings[i].rx_q = ((proc_type == RTE_PROC_PRIMARY) ? rte_ring_create(q_name,
                ringsize, socket_id, 0) : rte_ring_lookup(get_rx_queue_name(i)));
        if (client_rings[i].rx_q == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create rx ring queue for client %u\n", i);
        LOG_INFO("rx_ring: %s:%p", q_name, client_rings[i].rx_q);

        if (proc_type == RTE_PROC_PRIMARY) {
            rte_ring_create(get_arp_ring_name(i), 1024, socket_id, 0);
        }
        if (i == proc_id) {
            shadow_arp_ring = rte_ring_lookup(get_arp_ring_name(i));
            if (!shadow_arp_ring) {
                LOG_ERROR("Proc %d: Failed to lookup ARP ring", proc_id);
            }
        }
    }
    return 0;
}

static inline char *get_mbuf_pool_name(int id) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "MBUF_POOL_%d", id);
    return buf;
}

int dpdk_init(int argc, char **argv)
{
    enum rte_proc_type_t proc_type;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    argc -= ret;

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) {
        rte_exit(EXIT_FAILURE, "Error: number of ports must be at least 1");
    }

    unsigned int num_mbufs = (nb_procs + 1) * MBUF_CACHE_SIZE;
    num_mbufs += nb_procs * CLIENT_QUEUE_RINGSIZE;
    num_mbufs += nb_procs * (RX_RING_SIZE + TX_RING_SIZE);
    proc_type = rte_eal_process_type();
    
    if (proc_type == RTE_PROC_PRIMARY) {
        for (int i = 0; i < nb_procs; i++) {
            struct rte_mempool *pool = rte_pktmbuf_pool_create(get_mbuf_pool_name(i), num_mbufs * nb_ports,
                MBUF_CACHE_SIZE, 0, JUMBO_FRAME_MAX_SIZE + RTE_PKTMBUF_HEADROOM, rte_socket_id());
            if (!pool) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %d\n", i);
            if (i == proc_id) mbuf_pool = pool;
        }
    } else {
        mbuf_pool = rte_mempool_lookup(get_mbuf_pool_name(proc_id));
        if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Cannot lookup mbuf pool %d\n", proc_id);
    }
    configure_tx_buffer(0, BURST_SIZE);

    init_shm_rings(proc_type);

    /* Initializing all ports. 8< */
    if (proc_type == RTE_PROC_PRIMARY) {
        RTE_ETH_FOREACH_DEV(portid)
            if (port_init(portid, mbuf_pool) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
    }
    /* only have 1 port: 0 */
    uint8_t port = 0;
    if (proc_type != RTE_PROC_PRIMARY) {
        ret = rte_eth_macaddr_get(port, &dpdk_port_addr);
        if (ret != 0)
            return ret;
        LOG_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                port, RTE_ETHER_ADDR_BYTES(&dpdk_port_addr));
    }
    /* >8 End of initializing all ports. */

    return argc;
}

void dpdk_cleanup()
{
    rte_eal_cleanup();
}

/*
 * virt_interface
 */
void open_interface(char *if_name)
{
    v_f_dpdk = virt_if_create(if_name);
    virt_if_attach(v_f_dpdk, (const uint8_t *)&dpdk_port_addr);
    
    // Explicitly enable checksum offload bypass for DPDK/Memif backend
    virt_if_enable_offload(v_f_dpdk);

    virt_if_register_callbacks(v_f_dpdk, gen_if_output, NULL);
}

void dpdk_set_virt_if(struct virt_interface *vif)
{
    v_f_dpdk = vif;
}

void set_mtu(int mtu)
{
    if (v_f_dpdk) {
        LOG_INFO("Setting MTU to %d", mtu);
        if (virt_if_set_mtu(v_f_dpdk, mtu) != 0) {
            LOG_ERROR("Failed to set MTU to %d", mtu);
        }
        // Also update DPDK port MTU
        if (rte_eth_dev_set_mtu(0, mtu) != 0) {
            LOG_INFO("Failed to set DPDK port MTU to %d", mtu);
        }
    } else {
        LOG_ERROR("Failed to set MTU: Interface not initialized");
    }
}

void configure_interface(char *ip_addr, char *gateway_addr)
{
    LOG_INFO("Configuring interface with IP %s, Gateway %s", ip_addr, gateway_addr);
    struct in_addr addr, gw;
    inet_pton(AF_INET, ip_addr, &addr);
    inet_pton(AF_INET, gateway_addr, &gw);
    unsigned netmask = 24; // Assuming /24 netmask
    virt_if_add_addr(v_f_dpdk, &addr, netmask, 1);
    virt_if_add_gateway(v_f_dpdk, &gw);
    LOG_INFO("Interface configured.");
}

void add_interface_ip(char *ip_addr)
{
    LOG_INFO("Adding IP %s to interface", ip_addr);
    struct in_addr addr;
    inet_pton(AF_INET, ip_addr, &addr);
    unsigned netmask = 24; // Assuming /24 netmask
    virt_if_add_addr(v_f_dpdk, &addr, netmask, 1);
}
