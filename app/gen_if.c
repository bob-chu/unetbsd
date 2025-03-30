#include "string.h"
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ring.h>

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

static struct virt_interface *v_if;
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
static struct rte_ether_addr addr;
static uint8_t num_queue;
static struct client_ring *client_rings;
static struct client_ring curr_client_ring;

static int nb_procs = 1;
static int proc_id = 0;

struct client_rx_buf {
	struct rte_mbuf *buffer[BURST_SIZE];
	uint16_t count;
};

/* One buffer per client rx queue - dynamically allocate array */
static struct client_rx_buf *cl_rx_buf;

lb_func_t gl_lb_callback;

void register_lb_callback(lb_func_t lb_callback)
{
    gl_lb_callback = lb_callback;
}

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    uint16_t rx_rings = PORT_QUEUE_SZ, tx_rings = PORT_QUEUE_SZ;
    if (nb_procs > 1) {
        rx_rings = tx_rings = nb_procs;
    }

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = symmetric_rsskey,
                .rss_key_len = sizeof(symmetric_rsskey),
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
            }
        }
    };

    memset(&port_conf, 0, sizeof(port_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        LOG_INFO("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    retval = rte_eth_macaddr_get(0, &addr);
    if (retval != 0)
        return retval;

    LOG_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
            " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            port, RTE_ETHER_ADDR_BYTES(&addr));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

void dump_mbuf_hex(struct rte_mbuf *mbuf)
{
    return;

    if (!mbuf) {
        LOG_INFO("Invalid mbuf\n");
        return;
    }

    // Get the pointer to the data and the data length
    const uint8_t *data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    uint16_t data_len = rte_pktmbuf_data_len(mbuf);

    printf("Mbuf data dump (length=%u):\n", data_len);

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

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    LOG_INFO("OUT to QUEUE  %d: <<<<\n", proc_id);
    dump_mbuf_hex(m);
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
        if (!data){
            break;
        }
        rte_memcpy(data, iov[i].iov_base, iov[i].iov_len);
    }

    return send_single_packet(buf, 0);

out:
    return 0;
}

static void single_mbuf_input(struct rte_mbuf *pkt)
{
    LOG_INFO("IN from QUEUE: %d: >>>>\n", proc_id);
    dump_mbuf_hex(pkt);
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
            rte_pktmbuf_free(pkt);
            flag = false;
            return;
        }
        pn = pn->next;
        prev = mb;
    }
    if (flag)
        virt_if_mbuf_input(v_if, hdr);

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
    LOG_INFO("send packet to rx_queue [%u]", client);
    cl_rx_buf[client].buffer[cl_rx_buf[client].count++] = buf;
    if (cl_rx_buf[client].count > (BURST_SIZE-2)) {
        flush_rx_queue(client);
    }
}

void port_read(uint8_t queue_id)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    const uint16_t nb_rx = rte_eth_rx_burst(0,
            proc_id,
            bufs, BURST_SIZE);

    if (unlikely(nb_rx == 0))
       return;

    LOG_INFO("read packet [%d] from port [%d]", nb_rx, proc_id);
    for (int i = 0; i < nb_rx; i++) {
        struct rte_mbuf *pkt = bufs[i];
        rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
        if (is_arp_packet(pkt)) {
            for (int j = 0; j < nb_procs; j++) {
                LOG_INFO("send arp packet to ring[%d]", j);
                if (j != proc_id) {
                    struct rte_mbuf * cloned_pkt = rte_pktmbuf_clone(pkt, mbuf_pool);
                    if (cloned_pkt) {
                        enqueue_rx_packet(j, cloned_pkt);
                    }
                }
            }
        }

        if (gl_lb_callback) {
            int prot = 0;
            uint16_t src_port = 0, dst_port = 0;
            get_ports(pkt, &prot, &src_port, &dst_port);
            uint16_t queue_id = gl_lb_callback(prot, src_port, dst_port);
            //if (queue_id != ff_global_cfg.dpdk.proc_id) {
            //rte_ring_mp_enqueue(client_rings[0].rx_q, pkt);
            enqueue_rx_packet(queue_id, pkt);
                //continue;
            //}
        } else {
            enqueue_rx_packet(0, pkt);
        }
        //single_mbuf_input(pkt);
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

    LOG_INFO("read packet [%d] from ring [%d]", rx_pkts, proc_id);
    for (i = 0; i < rx_pkts; i++) {
        struct rte_mbuf *buf = (struct rte_mbuf *)pkts[i];
        single_mbuf_input(buf);
    }
}

void dpdk_read()
{
    rte_eth_tx_buffer_flush(0, proc_id, tx_buffer);
    port_read(proc_id);
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
    }
    return 0;
}

int dpdk_init(int argc, char **argv)
{
    static const char *_MBUF_POOL = "MBUF_POOL";
    enum rte_proc_type_t proc_type;
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    argc -= ret;

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1) {
		rte_exit(EXIT_FAILURE, "Error: number of ports must be 1");
    }

    unsigned int num_mbufs = (nb_procs + 1) * MBUF_CACHE_SIZE;
    num_mbufs += nb_procs * CLIENT_QUEUE_RINGSIZE;
    num_mbufs += nb_procs * (RX_RING_SIZE + TX_RING_SIZE);
    proc_type = rte_eal_process_type();
    /* Allocates mempool to hold the mbufs. 8< */
    mbuf_pool =  (proc_type == RTE_PROC_SECONDARY) ?
        rte_mempool_lookup(_MBUF_POOL) :
        rte_pktmbuf_pool_create("MBUF_POOL", num_mbufs * nb_ports,
            MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    /* >8 End of allocating mempool to hold mbuf. */

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
    configure_tx_buffer(0, BURST_SIZE);

    init_shm_rings(proc_type);

    /* Initializing all ports. 8< */
    if (proc_type == RTE_PROC_PRIMARY) {
        RTE_ETH_FOREACH_DEV(portid)
            if (port_init(portid, mbuf_pool) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                        portid);
    }
    /* only have 1 port: 0 */
    uint8_t port = 0;
    if (proc_type != RTE_PROC_PRIMARY) {
        /* Display the port MAC address. */
        ret = rte_eth_macaddr_get(port, &addr);
        if (ret != 0)
            return ret;
        LOG_INFO("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
                " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
                port, RTE_ETHER_ADDR_BYTES(&addr));


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
    v_if = virt_if_create(if_name);
    virt_if_attach(v_if, (const uint8_t *)&addr);

    virt_if_register_callbacks(v_if, gen_if_output, NULL);

    char *ip_str = "192.168.1.2";
    char *netmask_str = "255.255.255.0";
    char *gateway_str = "192.168.1.1";

    struct in_addr addr, gw;
    inet_pton(AF_INET, ip_str, &addr);
    inet_pton(AF_INET, gateway_str, &gw);
    unsigned netmask = 24;
    //inet_pton(AF_INET, netmask_str, &netmask);
    virt_if_add_addr(v_if, &addr, netmask, 1);
    virt_if_add_gateway(v_if, &gw);
}
