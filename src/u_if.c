
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
    int total = m->m_pkthdr.len;
    int ret = gl_vif->output_cb((void *)m, total, gl_vif->sc_arg);
    if (ret == 1) {
        // Callback took ownership of mbuf (e.g., for queuing)
        return 0;
    }
    m_freem(m); // Free the mbuf after the callback if not taken
    return 0;
}

int
ifioctl_virt(struct ifnet *ifp, u_long cmd, void *data)
{
    // Handle MTU-related ioctls to support jumbo frames
    switch (cmd) {
        case SIOCSIFMTU:
            ifp->if_mtu = *(int *)data;
            if (ifp->if_mtu > 9216) {
                ifp->if_mtu = 9216; // Cap at 9216 for jumbo frame support
            }
            return 0;
        case SIOCGIFMTU:
            *(int *)data = ifp->if_mtu;
            return 0;
        default:
            return 0;
    }
}

struct virt_interface *virt_if_create(const char *name)
{
    static if_index_t gl_if_index = 0;

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
    ifp->if_mtu = 1500; // Match standard Linux MTU
    ifp->if_flags = IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_RUNNING;
    ifp->if_init = virt_if_init;
    ifp->if_start = virt_if_start;
    ifp->if_type = IFT_ETHER;
    ifp->if_addrlen = ETHER_ADDR_LEN;
    ifp->if_hdrlen = ETHER_HDR_LEN;
    ifp->if_index = gl_if_index;
    gl_if_index++;
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
    printf("[u_if] virt_if_attach: attaching interface with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
           ether_addr[0], ether_addr[1], ether_addr[2], ether_addr[3], ether_addr[4], ether_addr[5]);
    printf("[u_if] Before ether_ifattach: flags=0x%x\n", gl_vif->ifp->if_flags);
    
    ether_ifattach(gl_vif->ifp, ether_addr);
    gl_vif->ifp->if_mtu = 1500; // Match standard Linux MTU (was 9000)
    
    // Disable hardware checksum offload by default
    gl_vif->ifp->if_capabilities = 0;
    gl_vif->ifp->if_capenable = 0;
    
    printf("[u_if] After ether_ifattach: flags=0x%x, if_output=%p, if_transmit=%p\n",

           gl_vif->ifp->if_flags, gl_vif->ifp->if_output, gl_vif->ifp->if_transmit);
    
    return 0;
}

void virt_if_enable_offload(struct virt_interface *vif)
{
    if (!vif || !vif->ifp) return;
    
    // Enable software-bypass checksum offload (we trust the virtual transport)
    vif->ifp->if_capabilities = IFCAP_CSUM_IPv4_Tx | IFCAP_CSUM_IPv4_Rx |
                                   IFCAP_CSUM_TCPv4_Tx | IFCAP_CSUM_TCPv4_Rx |
                                   IFCAP_CSUM_UDPv4_Tx | IFCAP_CSUM_UDPv4_Rx |
                                   IFCAP_CSUM_TCPv6_Tx | IFCAP_CSUM_TCPv6_Rx |
                                   IFCAP_CSUM_UDPv6_Tx | IFCAP_CSUM_UDPv6_Rx;
    vif->ifp->if_capenable = vif->ifp->if_capabilities;
    
    vif->ifp->if_csum_flags_tx = M_CSUM_IPv4 | M_CSUM_TCPv4 | M_CSUM_UDPv4 | 
                                   M_CSUM_TCPv6 | M_CSUM_UDPv6;
    vif->ifp->if_csum_flags_rx = M_CSUM_IPv4 | M_CSUM_TCPv4 | M_CSUM_UDPv4 | 
                                   M_CSUM_TCPv6 | M_CSUM_UDPv6;
    
    printf("[u_if] Offload enabled: caps=0x%x\n", vif->ifp->if_capabilities);
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

int virt_if_input(struct virt_interface *vif, void *data, size_t len)
{
    vif = gl_vif;
    struct mbuf *m;

    if (!gl_vif || !gl_vif->ifp) {
        return -1;
    }

    if (len >= 14) {
        uint8_t *eb = (uint8_t *)data;
        uint16_t et = (eb[12] << 8) | eb[13];
        // printf("[u_if] virt_if_input: len=%zu, eth_type=0x%04x, dst=%02x:%02x:%02x:%02x:%02x:%02x\n", 
        //        len, et, eb[0], eb[1], eb[2], eb[3], eb[4], eb[5]);
    }

    if (len <= MCLBYTES) {
        m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
        if (!m) {
            return -1;
        }
        m->m_data += 32; // Reserve space for headers
        if (len > M_TRAILINGSPACE(m)) {
            m_free(m);
            return -1;
        }
        u_memcpy(m->m_data, data, len);
        m->m_len = len;
    } else {
        // Handle jumbo frames by chaining mbufs
        m = netbsd_mget_hdr(data, len);
        if (!m) {
            return -1;
        }
    }

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

    if (vif == NULL || vif->ifp == NULL) {
        return -1;
    }

    printf("[u_if] virt_if_add_addr4: Adding IP %d.%d.%d.%d/%u to interface %s\n",
           (addr->s_addr >> 0) & 0xff, (addr->s_addr >> 8) & 0xff,
           (addr->s_addr >> 16) & 0xff, (addr->s_addr >> 24) & 0xff,
           netmask, vif->ifp->if_xname);

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


static int
virt_if_add_addr6(struct virt_interface *vif, struct in6_addr *addr, unsigned netmask)
{
    struct in6_aliasreq ifra6;
    struct sockaddr_in6 sin6, mask6;
    struct in6_addrlifetime lifetime6;
    vif = gl_vif;
    if (vif == NULL || vif->ifp == NULL) {
        return -1;
    }

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_len = sizeof(sin6);
    sin6.sin6_family = AF_INET6;
    memcpy(sin6.sin6_addr.s6_addr, addr->s6_addr, sizeof(addr->s6_addr));

    memset(&mask6, 0, sizeof(mask6));
    mask6.sin6_len = sizeof(mask6);
    mask6.sin6_family = AF_INET6;
    in6_prefixlen2mask(&mask6.sin6_addr, netmask);
    lifetime6.ia6t_vltime = 0xffffffff;
    lifetime6.ia6t_pltime = 0xffffffff;
 
    memset(&ifra6, 0, sizeof(ifra6));
    ifra6.ifra_addr = sin6;
    ifra6.ifra_prefixmask = mask6;
    ifra6.ifra_lifetime = lifetime6;

    return in6_control(NULL, SIOCAIFADDR_IN6, (void *)&ifra6, vif->ifp);
}



int
virt_if_add_addr(struct virt_interface *vif, void *addr, unsigned netmask, int is_ipv4)
{
    if (is_ipv4) {
        return virt_if_add_addr4(vif, (struct in_addr *)addr, netmask);
    } else {
        return virt_if_add_addr6(vif, (struct in6_addr *)addr, netmask);
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

    clear_sinaddr(&dst);
    clear_sinaddr(&mask);
    clear_sinaddr(&gw);
    gw.sin_addr = *gw_addr;

    int error = rtrequest(RTM_ADD, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
                            (struct sockaddr *)&mask, RTF_UP | RTF_GATEWAY | RTF_STATIC,
                            NULL);
    if (error != 0) {
        printf("Failed to add gateway: error=%d\n", error);
        return;
    }
}

void
virt_if_add_gateway6(struct virt_interface *vif, void *addr)
{

    struct in6_addr *gw_addr = (struct in6_addr *)addr;
    struct sockaddr_in6 dst, mask, gw;

    bzero(&dst, sizeof(dst));
    bzero(&mask, sizeof(mask));
    bzero(&gw, sizeof(gw));

    dst.sin6_len = mask.sin6_len = gw.sin6_len =
        sizeof(struct sockaddr_in6);
    dst.sin6_family = gw.sin6_family = AF_INET6;

    memcpy(gw.sin6_addr.s6_addr, gw_addr->s6_addr, sizeof(gw_addr->s6_addr));

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
    m_freem(mbuf);
}

void *netbsd_mget_hdr(void *data, int len)
{
    struct mbuf *m, *m_curr;
    int remaining = len;
    int chunk;
    char *p = (char *)data;

    /* Allocate the header mbuf */
    if (remaining > MHLEN) {
        m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
    } else {
        m = m_gethdr(M_NOWAIT, MT_DATA);
    }

    if (m == NULL) return NULL;

    chunk = M_TRAILINGSPACE(m);
    if (chunk > remaining) chunk = remaining;

    u_memcpy(m->m_data, p, chunk);
    m->m_len = chunk;
    p += chunk;
    remaining -= chunk;

    m_curr = m;
    while (remaining > 0) {
        struct mbuf *n;
        if (remaining > MLEN) {
            n = m_getcl(M_NOWAIT, MT_DATA, 0);
        } else {
            MGET(n, M_NOWAIT, MT_DATA);
        }

        if (n == NULL) {
            m_freem(m);
            return NULL;
        }

        chunk = M_TRAILINGSPACE(n);
        if (chunk > remaining) chunk = remaining;

        u_memcpy(n->m_data, p, chunk);
        n->m_len = chunk;
        p += chunk;
        remaining -= chunk;

        m_curr->m_next = n;
        m_curr = n;
    }

    m->m_pkthdr.len = len;
    m->m_pkthdr._rcvif.index = gl_vif->ifp->if_index;
    return m;
}

void *netbsd_mget_data(void *pre, void *data, int len)
{
    struct mbuf *m_prev = (struct mbuf *)pre;
    struct mbuf *m_new_head = NULL;
    struct mbuf *m_curr = NULL;
    int remaining = len;
    int chunk;
    char *p = (char *)data;

    while (remaining > 0) {
        struct mbuf *n;
        if (remaining > MLEN) {
            n = m_getcl(M_NOWAIT, MT_DATA, 0);
        } else {
            MGET(n, M_NOWAIT, MT_DATA);
        }

        if (n == NULL) {
            if (m_new_head) m_freem(m_new_head);
            return NULL;
        }

        chunk = M_TRAILINGSPACE(n);
        if (chunk > remaining) chunk = remaining;

        u_memcpy(n->m_data, p, chunk);
        n->m_len = chunk;
        p += chunk;
        remaining -= chunk;

        if (m_new_head == NULL) {
            m_new_head = n;
        } else {
            m_curr->m_next = n;
        }
        m_curr = n;
    }

    if (m_prev != NULL && m_new_head != NULL) {
        m_prev->m_next = m_new_head;
    }

    return m_curr; // Return the LAST mbuf in the new chain
}

int virt_if_mbuf_input(struct virt_interface *vif, void *data)
{
    if (data == NULL) {
        return -1;
    }
    ether_input(gl_vif->ifp, data);
    return 0;
}

int virt_if_set_mtu(struct virt_interface *vif, int mtu)
{
    if (!vif || !vif->ifp) return -1;
    return ifioctl_virt(vif->ifp, SIOCSIFMTU, &mtu);
}

// Get veth file descriptor for polling (stub for now)
int virt_if_get_fd(void)
{
    return -1;
}

// Wrapper to copy data out of mbuf chain
void netbsd_mbuf_copydata(struct mbuf *m, int off, int len, void *out)
{
    m_copydata(m, off, len, out);
}

