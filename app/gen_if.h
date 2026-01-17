#ifndef __GEN_IF_H__
#define __GEN_IF_H__

typedef int (*loop_func_t)(void *arg);
typedef int (*lb_func_t)(int prot, uint16_t src_port, uint16_t dst_port);

void register_lb_callback(lb_func_t lb_callback);
void gen_run(loop_func_t loop, void *arg);
int gen_if_up(void);
int dpdk_init(int argc, char **argv);
void open_interface(char *if_name);
void configure_interface(char *ip_addr, char *gateway_addr);
void add_interface_ip(char *ip_addr);
void single_mbuf_input(struct rte_mbuf *pkt);
void set_mtu(int mtu);
void dpdk_read();
void dump_mbuf_hex(struct rte_mbuf *mbuf, char *msg);

// DPDK exports for shim integration
extern struct virt_interface *v_f_dpdk;
extern struct rte_ether_addr dpdk_port_addr;
void dpdk_set_virt_if(struct virt_interface *vif);
int dpdk_wait_link_up(int timeout_ms);
int gen_if_output(void *m, long unsigned int total, void *arg);

struct client_ring {
	struct rte_ring *rx_q;
	unsigned client_id;
	/* these stats hold how many packets the client will actually receive,
	 * and how many packets were dropped because the client's queue was full.
	 * The port-info stats, in contrast, record how many packets were received
	 * or transmitted on an actual NIC port.
	 */
	struct {
		volatile uint64_t rx;
		volatile uint64_t rx_drop;
	} stats;
};

#define MP_CLIENT_RXQ_NAME "MProc_Client_%u_RX"
/*
 * Given the rx queue name template above, get the queue name
 */
static inline const char *
get_rx_queue_name(uint8_t id)
{
	/* buffer for return value. Size calculated by %u being replaced
	 * by maximum 3 digits (plus an extra byte for safety) */
	static char buffer[sizeof(MP_CLIENT_RXQ_NAME) + 2];

	snprintf(buffer, sizeof(buffer), MP_CLIENT_RXQ_NAME, id);
	return buffer;
}

#endif
