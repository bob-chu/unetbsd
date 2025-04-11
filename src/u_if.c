
#include "stub.h"
#include <sys/container_of.h>
#include <net/if_ether.h>
#include "u_if.h"
#include "u_mem.h"

static struct virt_interface *gl_vif = NULL;
int virt_if_output(struct virt_interface *vif, void *data, size_t len);
int virt_if_input(struct virt_interface *vif, void *data, size_t len);

static int virt_if_init(struct ifnet *ifp) {
    ifp->if_flags |= IFF_RUNNING;
    return 0;
}

static void virt_if_start(struct ifnet *ifp)
{
}

int virt_transmit(struct ifnet *ifp, struct mbuf *m)
{
    char data[4096];
    int total = m->m_pkthdr.len;
    int off = 0;
    int len = total;
    struct mbuf *mb = (struct mbuf *)m;
    char *data_ptr = mtod(m, char *);

    //printf(">>>>: %u: %d\n", m->m_pkthdr.len,  total);
    /*
    while (total > 0) {
        if (off + total > sizeof(data)) {
            printf("buf[4096] is less than mbuf size: %d\n", total);
            goto out;
        }
        m_copydata(mb, 0, total, data);
        total -= total;
    }
    */
    //gl_vif->output_cb((void *)data_ptr, len, gl_vif->sc_arg);
    gl_vif->output_cb((void *)m, len, gl_vif->sc_arg);
out:
    m_freem((struct mbuf *)mb);
    return 0;
}

int
ifioctl_virt(struct ifnet *ifp, u_long cmd, void *data)
{
    return 0;
}

struct virt_interface *virt_if_create(const char *name)
{
    static if_index_t gl_if_index;

    gl_vif = malloc(sizeof(struct virt_interface));
    if (!gl_vif) return NULL;

    //struct ifnet *ifp = malloc(sizeof(struct ifnet));
    struct ifnet *ifp = calloc(1, sizeof(struct ethercom));
    if (!ifp) {
        free(gl_vif);
        return NULL;
    }

    memset(ifp, 0, sizeof(*ifp));
    strlcpy(ifp->if_xname, "virt0", IFNAMSIZ);
    ifp->if_softc = gl_vif;
    ifp->if_mtu = ETHERMTU;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST |IFF_UP | IFF_RUNNING;
    ifp->if_init = virt_if_init;
    ifp->if_start = virt_if_start;
    ifp->if_type = IFT_ETHER;
    ifp->if_addrlen = ETHER_ADDR_LEN;
    ifp->if_hdrlen = ETHER_HDR_LEN;
    ifp->if_index = gl_if_index++;
    ifp->if_transmit = virt_transmit;
    ifp->if_ioctl = ifioctl_virt;

    gl_vif->ifp = ifp;
    gl_vif->output_cb = NULL;
    gl_vif->input_cb = NULL;

    //if_attach(ifp);
    if_initialize(ifp);
    //ether_ifattach(ifp, enaddr);
    if_register(ifp);
    return gl_vif;
}

int
virt_if_attach(struct virt_interface *vif, const uint8_t *ether_addr)
{
    /*
    if (vif == NULL || vif->ifp == NULL) {
        return -1;
    }
    */
    ether_ifattach(gl_vif->ifp, ether_addr);
    return 0;
}

int virt_if_register_callbacks(struct virt_interface *vif,
                               virt_if_output_cb out_cb,
                               virt_if_input_cb in_cb) {
    if (!vif) return -1;
    vif->output_cb = out_cb;
    vif->input_cb = in_cb;
    return 0;
}

int virt_if_output(struct virt_interface *vif, void *data, size_t len) {

    return gl_vif->output_cb(data, len, gl_vif->sc_arg);
}

int virt_if_input(struct virt_interface *vif, void *data, size_t len) {
    //if (!vif || !vif->input_cb) return -1;
    vif = gl_vif;
    struct mbuf *m;
    m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
    if (!m) return -1;
#if 0
    if (len > MHLEN) {
        m_free(m);
        return -1;
    }
#endif
    m->m_data += 32;
    u_memcpy(m->m_data, data, len);
    m->m_len = len;
    m->m_pkthdr.len = len;
    m->m_pkthdr._rcvif.index = vif->ifp->if_index;

    ether_input(gl_vif->ifp, m);
    return 0;
}

static int
virt_if_add_addr4(struct virt_interface *vif, struct in_addr *addr, unsigned netmask)
{
    struct in_aliasreq ifra;
    struct sockaddr_in sin, mask;
    vif = gl_vif;
    if (vif == NULL || vif->ifp == NULL) {
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = *addr;

    memset(&mask, 0, sizeof(mask));
    mask.sin_len = sizeof(mask);
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = htonl(0xffffffff << (32 - netmask));

    memset(&ifra, 0, sizeof(ifra));
    ifra.ifra_addr = sin;
    ifra.ifra_mask = mask;

    return in_control(NULL, SIOCAIFADDR, (void *)&ifra, vif->ifp);
}

int
virt_if_add_addr(struct virt_interface *vif, void *addr, unsigned netmask, int is_ipv4)
{
    if (is_ipv4) {
        return virt_if_add_addr4(vif, (struct in_addr *)addr, netmask);
    } else {
        printf("IPv6 address setting not implemented yet\n");
        return -1;
    }
}

static void
clear_sinaddr(struct sockaddr_in *sin)
{

	bzero(sin, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = INADDR_ANY; /* XXX: htonl(INAADDR_ANY) ? */
	sin->sin_port = 0;
}


void
virt_if_add_gateway(struct virt_interface *vif, void *addr)
{
    struct in_addr *gw_addr = (struct in_addr *)addr;
    struct sockaddr_in dst;
    struct sockaddr_in gw;
    struct sockaddr_in mask;

    // 初始化地址结构
    clear_sinaddr(&dst);   // 默认路由：0.0.0.0
    clear_sinaddr(&mask);  // 默认掩码：0.0.0.0
    clear_sinaddr(&gw);    // 网关地址
    gw.sin_addr = *gw_addr;

    // 添加路由
    //int error = rtrequest_fib(RTM_ADD, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
    int error = rtrequest(RTM_ADD, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
                            (struct sockaddr *)&mask, RTF_UP | RTF_GATEWAY | RTF_STATIC,
                            NULL);
    if (error != 0) {
        printf("Failed to add gateway: error=%d\n", error);
        return;
    }
}

/*
 * Copy segments to iov[].  Returns length, or -1 if iov does not fit.
 */
long netbsd_mbufvec(void *mp, struct iovec *iov, int *n_iov)
{
    struct mbuf *m = mp;
    int n, limit;
    long len;

    len = 0;
    limit = *n_iov;
    for (n = 0; ((m != NULL) && (n < limit)); n++) {
        iov[n].iov_base = mtod(m, char *);
        iov[n].iov_len = m->m_len;
        len += m->m_len;
        m = m->m_next;
    }
    *n_iov = n;
    return len;
}

void netbsd_freembuf(void *mbuf) {
    m_free(mbuf);
}

void *netbsd_mget_hdr(void *data, int len)
{
    struct mbuf *m;
    m = m_gethdr(M_NOWAIT, MT_DATA);
    if (m == NULL) {
        return NULL;
    }
    m->m_pkthdr.len = len;
    m->m_pkthdr._rcvif.index =gl_vif->ifp->if_index;
    if (len > MHLEN) {
        m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
        if (m->m_ext.ext_buf == NULL) {
            return NULL;
        }
        u_memcpy(m->m_data, data, len);
        m->m_len = len;
    } else {
        u_memcpy(m->m_data, data, len);
        m->m_len = len;
    }
    return m;
}

void *netbsd_mget_data(void *pre, void *data, int len)
{
    struct mbuf *m_new = NULL;
    if (len > MLEN) {
        m_new = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
        if (m_new == NULL) {
            return NULL;
        }
    } else {
        MGET(m_new, M_NOWAIT, MT_DATA);
        if (m_new == NULL) {
            return NULL;
        }
    }
    u_memcpy(m_new->m_data, data, len);
    m_new->m_len = len;
    return m_new;
}

int virt_if_mbuf_input(struct virt_interface *vif, void *data)
{
    if (data == NULL) {
        return -1;
    }
    ether_input(gl_vif->ifp, data);
}
