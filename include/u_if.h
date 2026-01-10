#ifndef __U_IF_H__
#define __U_IF_H__

//#include "stub.h"
//#include <net/if_ether.h>

typedef int (*virt_if_output_cb)(void *data, size_t len, void *arg);
typedef int (*virt_if_input_cb)(void *data, size_t len, void *arg);

struct virt_interface {
    struct ifnet *ifp;
    void *sc_arg ;
    virt_if_output_cb output_cb;
    virt_if_input_cb input_cb;
};

struct virt_interface *virt_if_create(const char *name);

int virt_if_attach(struct virt_interface *vif, const uint8_t *ether_addr);
int virt_if_register_callbacks(struct virt_interface *vif,
                               virt_if_output_cb out_cb,
                               virt_if_input_cb in_cb);
int virt_if_output(struct virt_interface *vif, void *data, size_t len);
int virt_if_input(struct virt_interface *vif, void *data, size_t len);
int virt_if_mbuf_input(struct virt_interface *vif, void *data);

int virt_if_add_addr(struct virt_interface *vif, void *addr, unsigned netmask, int is_ipv4);
void virt_if_add_gateway(struct virt_interface *vif, void *addr);
void virt_if_add_gateway6(struct virt_interface *vif, void *addr);
int virt_if_set_mtu(struct virt_interface *vif, int mtu);


long netbsd_mbufvec(void *mp, struct iovec *iov, int *n_iov);
void netbsd_freembuf(void *mbuf);


void *netbsd_mget_hdr(void *data, int len);
void *netbsd_mget_data(void *pre, void *data, int len);
int virt_if_get_fd(void);  // Get veth file descriptor for polling
#endif
