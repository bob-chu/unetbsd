#ifndef __COMMON_H__
#define __COMMON_H__

#include <rte_ether.h>

#define MAX_CONN_SIZE 8192
#define CLIENT_SHM_PATH "/tmp/ptm_client_stats"
#define SERVER_SHM_PATH "/tmp/ptm_server_stats"

#define LB_SHARED_MEMZONE "lb_shared_memzone"

struct lb_shared_info {
	struct rte_ether_addr port_mac;
};

#endif
