#define _GNU_SOURCE
#include <dlfcn.h>
#include <poll.h>
#include <sys/select.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "u_socket.h"
#include "u_fd.h"
#include "u_if.h"
#include "cJSON.h"



// Real libc function pointers
static int (*real_socket)(int, int, int) = NULL;
static int (*real_close)(int) = NULL;
static ssize_t (*real_read)(int, void*, size_t) = NULL;
static ssize_t (*real_write)(int, const void*, size_t) = NULL;
static int (*real_poll)(struct pollfd*, nfds_t, int) = NULL;
static int (*real_bind)(int, const struct sockaddr*, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static int (*real_accept)(int, struct sockaddr*, socklen_t*) = NULL;
static int (*real_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static ssize_t (*real_send)(int, const void*, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void*, size_t, int) = NULL;
static int (*real_getsockopt)(int, int, int, void*, socklen_t*) = NULL;
static int (*real_setsockopt)(int, int, int, const void*, socklen_t) = NULL;
static int (*real_fcntl)(int, int, ...) = NULL;
static int (*real_ioctl)(int, unsigned long, ...) = NULL;
static int (*real_select)(int, fd_set*, fd_set*, fd_set*, struct timeval*) = NULL;
static ssize_t (*real_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = NULL;
static ssize_t (*real_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*) = NULL;
static int (*real_shutdown)(int, int) = NULL;
static int (*real_getsockname)(int, struct sockaddr*, socklen_t*) = NULL;
static int (*real_getpeername)(int, struct sockaddr*, socklen_t*) = NULL;
static int (*real_pselect)(int, fd_set*, fd_set*, fd_set*, const struct timespec*, const sigset_t*) = NULL;
static int (*real_ppoll)(struct pollfd*, nfds_t, const struct timespec*, const sigset_t*) = NULL;

// Backend types
enum shim_backend {
    BACKEND_AF_PACKET = 0,
    BACKEND_DPDK
};

// Configuration structure
struct shim_config {
    char if_name[16];
    uint8_t mac[6];
    uint32_t ip;
    uint32_t netmask;
    uint32_t gateway;
    int mtu;
    int veth_fd;
    int debug;
    enum shim_backend backend;
    char dpdk_args[256];
};

// Global state
static pthread_t g_stack_thread;
static pthread_mutex_t g_lock; // Initialized in constructor
static int g_running = 0;
static int g_initialized = 0;
static int g_timer_fd = -1;
static int g_veth_fd = -1;
static int g_debug = 0;
static enum shim_backend g_backend = BACKEND_AF_PACKET;
static int g_rtc_mode = 0; // Run-to-Completion mode

// NetBSD stack hardclock
void user_hardclock(void);

// Debug helper
#define SHIM_LOG(fmt, ...) \
    do { if (g_debug) fprintf(stderr, "[Shim] " fmt, ##__VA_ARGS__); } while (0)

static void print_poll_events(int fd, short events, const char *prefix) {
    if (!g_debug || !events) return;
    fprintf(stderr, "%s fd=%d events=", prefix, fd);
    if (events & POLLIN) fprintf(stderr, "IN ");
    if (events & POLLOUT) fprintf(stderr, "OUT ");
    if (events & POLLERR) fprintf(stderr, "ERR ");
    if (events & POLLHUP) fprintf(stderr, "HUP ");
    if (events & POLLNVAL) fprintf(stderr, "NVAL ");
    fprintf(stderr, "\n");
}

#define SHIM_FD_OFFSET 500

static struct netbsd_handle *get_shim_handle(int fd) {
    if (fd < SHIM_FD_OFFSET) return NULL;
    int internal_fd = fd - SHIM_FD_OFFSET;
    // Assuming internal FDs are valid if fd_get returns something
    return fd_get(internal_fd);
}
static struct virt_interface *g_vif = NULL;
static int g_af_packet_fd = -1;  // AF_PACKET socket for external network

// Forward declarations
static void* stack_thread_func(void* arg);
static int drive_stack(void);

// Debug packet dump
static void dump_packet(const char *prefix, const uint8_t *data, size_t len)
{
    if (!g_debug) return;
    fprintf(stderr, "[Shim] %s: %zu bytes\n", prefix, len);
    for (size_t i = 0; i < len && i < 64; i++) {
        fprintf(stderr, "%02x ", data[i]);
        if ((i + 1) % 16 == 0) fprintf(stderr, "\n");
    }
    if (len > 64) fprintf(stderr, "... (%zu more bytes)", len - 64);
    fprintf(stderr, "\n");
    fflush(stderr);
}

// Translate NetBSD errno to Linux errno
static int translate_netbsd_errno(int nb_errno)
{
    switch (nb_errno) {
        case 0:  return 0;
        case 2:  return ENOENT;
        case 5:  return EIO;
        case 9:  return EBADF;
        case 11: return EAGAIN; // NetBSD was 11 in very old versions, but now 35
        case 12: return ENOMEM;
        case 13: return EACCES;
        case 14: return EFAULT;
        case 17: return EEXIST;
        case 19: return ENODEV;
        case 22: return EINVAL;
        case 23: return ENFILE;
        case 24: return EMFILE;
        case 32: return EPIPE;
        case 35: return EAGAIN; // Current NetBSD EAGAIN
        case 36: return EINPROGRESS;
        case 42: return 92; // NetBSD ENOPROTOOPT (42) -> Linux ENOPROTOOPT (92). Linux 42 is ENOMSG!
        case 45: return EOPNOTSUPP;
        case 48: return EADDRINUSE;
        case 49: return EADDRNOTAVAIL;
        case 50: return ENETDOWN;
        case 51: return ENETUNREACH;
        case 54: return ECONNRESET;
        case 56: return 106; // NetBSD EISCONN (56) -> Linux EISCONN (106).
        case 57: return 107; // NetBSD ENOTCONN (57) -> Linux ENOTCONN (107).
        case 60: return ETIMEDOUT;
        case 61: return ECONNREFUSED;
        case 65: return EHOSTUNREACH;
        default: return nb_errno; // Fallback
    }
}

// Robust lock helper - recovers from dead owner threads
static inline void lock_robust(void)
{
    int ret = pthread_mutex_lock(&g_lock);
    if (ret == EOWNERDEAD) {
        // Previous owner died while holding the lock, recover it
        fprintf(stderr, "[Shim] WARNING: Recovered mutex from dead thread\n");
        pthread_mutex_consistent(&g_lock);
    }
}

// Robust trylock helper - recovers from dead owner threads
static inline int trylock_robust(void)
{
    int ret = pthread_mutex_trylock(&g_lock);
    if (ret == EOWNERDEAD) {
        fprintf(stderr, "[Shim] WARNING: Recovered mutex from dead thread (trylock)\n");
        pthread_mutex_consistent(&g_lock);
        return 0;  // Successfully acquired
    }
    return ret;
}

// Batch I/O using sendmmsg/recvmmsg (PACKET_MMAP not supported in WSL2)
extern void netbsd_freembuf(void *mbuf);
extern long netbsd_mbufvec(void *mp, struct iovec *iov, int *n_iov);

// Batch TX queue for sendmmsg
#define BATCH_SIZE 32
static void *g_tx_queue[BATCH_SIZE];
static int g_tx_count = 0;

static void flush_tx_queue(void)
{
    if (g_tx_count == 0) return;
    if (g_af_packet_fd < 0) {
        for (int i = 0; i < g_tx_count; i++) {
            netbsd_freembuf(g_tx_queue[i]);
        }
        g_tx_count = 0;
        return;
    }

    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovs[BATCH_SIZE][16];
    memset(msgs, 0, sizeof(msgs));

    for (int i = 0; i < g_tx_count; i++) {
        int iov_cnt = 16;
        netbsd_mbufvec(g_tx_queue[i], iovs[i], &iov_cnt);
        msgs[i].msg_hdr.msg_iov = iovs[i];
        msgs[i].msg_hdr.msg_iovlen = iov_cnt;
    }

    int ret = sendmmsg(g_af_packet_fd, msgs, g_tx_count, 0);
    if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK && g_debug) {
        fprintf(stderr, "[Shim] sendmmsg failed: %s\n", strerror(errno));
    }

    for (int i = 0; i < g_tx_count; i++) {
        netbsd_freembuf(g_tx_queue[i]);
    }
    g_tx_count = 0;
}

// Packet output callback (NetBSD -> external network)
static int shim_packet_output(void *mbuf, size_t len, void *arg)
{
    if (g_debug) fprintf(stderr, "[Shim] Packet Output: %zu bytes\n", len);
    if (g_tx_count >= BATCH_SIZE) {
        flush_tx_queue();
    }
    g_tx_queue[g_tx_count++] = mbuf;
    return 1; // Tell u_if.c we took ownership
}

// Setup AF_PACKET socket for external network
static int setup_af_packet(const char *if_name)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    
    // Create AF_PACKET socket (use real_socket to avoid interception)
    int fd = real_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        fprintf(stderr, "[Shim] ERROR: Failed to create AF_PACKET socket: %s\n", strerror(errno));
        return -1;
    }
    
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    // Increase socket buffers to 8MB for better batch performance
    int buf_size = 8 * 1024 * 1024;
    real_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    real_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));

    // Get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "[Shim] ERROR: Interface %s not found: %s\n", if_name, strerror(errno));
        real_close(fd);
        return -1;
    }
    int if_index = ifr.ifr_ifindex;
    
    // Bind to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (real_bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "[Shim] ERROR: Failed to bind to %s: %s\n", if_name, strerror(errno));
        real_close(fd);
        return -1;
    }
    
    SHIM_LOG("AF_PACKET socket bound to %s (index %d)\n", if_name, if_index);
    return fd;
}



// Parse IP address from string
static uint32_t parse_ip(const char *str) {
    struct in_addr addr;
    return inet_pton(AF_INET, str, &addr) == 1 ? addr.s_addr : 0;
}

// Parse MAC address from string (XX:XX:XX:XX:XX:XX)
static int parse_mac(const char *str, uint8_t *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}


// Parse JSON config file (using cJSON)
static int load_json_config(const char *path, struct shim_config *cfg) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json_str = malloc(fsize + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }
    fread(json_str, 1, fsize, fp);
    fclose(fp);
    json_str[fsize] = 0;
    
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return -1;
    
    // Parse debug
    cJSON *debug = cJSON_GetObjectItem(root, "debug");
    if (debug && cJSON_IsString(debug)) {
        cfg->debug = atoi(cJSON_GetStringValue(debug));
    }
    
    // Parse gateway
    cJSON *gateway = cJSON_GetObjectItem(root, "gateway");
    if (gateway && cJSON_IsString(gateway)) {
        cfg->gateway = parse_ip(cJSON_GetStringValue(gateway));
    }
    
    // Parse interfaces array
    cJSON *interfaces = cJSON_GetObjectItem(root, "interfaces");
    if (interfaces && cJSON_IsArray(interfaces)) {
        cJSON *iface = cJSON_GetArrayItem(interfaces, 0);  // First interface
        if (iface) {
            cJSON *mac = cJSON_GetObjectItem(iface, "mac");
            if (mac && cJSON_IsString(mac)) {
                parse_mac(cJSON_GetStringValue(mac), cfg->mac);
            }
            
            cJSON *ip = cJSON_GetObjectItem(iface, "ip");
            if (ip && cJSON_IsString(ip)) {
                cfg->ip = parse_ip(cJSON_GetStringValue(ip));
            }
            
            cJSON *masklen = cJSON_GetObjectItem(iface, "masklen");
            if (masklen && cJSON_IsString(masklen)) {
                int ml = atoi(cJSON_GetStringValue(masklen));
                cfg->netmask = htonl(~((1 << (32 - ml)) - 1));
            }
            
            cJSON *mtu = cJSON_GetObjectItem(iface, "mtu");
            if (mtu && cJSON_IsString(mtu)) {
                cfg->mtu = atoi(cJSON_GetStringValue(mtu));
            }
            
            cJSON *param = cJSON_GetObjectItem(iface, "param");
            if (param && cJSON_IsString(param)) {
                strncpy(cfg->if_name, cJSON_GetStringValue(param), 
                        sizeof(cfg->if_name) - 1);
            }
        }
    }

    // Parse backend and DPDK args
    cJSON *backend = cJSON_GetObjectItem(root, "backend");
    if (backend && cJSON_IsString(backend)) {
        if (strcmp(cJSON_GetStringValue(backend), "dpdk") == 0) {
            cfg->backend = BACKEND_DPDK;
        } else {
            cfg->backend = BACKEND_AF_PACKET;
        }
    }

    cJSON *dpdk_args = cJSON_GetObjectItem(root, "dpdk_args");
    if (dpdk_args && cJSON_IsString(dpdk_args)) {
        strncpy(cfg->dpdk_args, cJSON_GetStringValue(dpdk_args), sizeof(cfg->dpdk_args) - 1);
    }
    
    cJSON_Delete(root);
    return 0;
}

// Load configuration (JSON file + env var overrides)
static void load_config(struct shim_config *cfg) {
    const char *env;
    
    // Set defaults
    strcpy(cfg->if_name, "veth0");
    cfg->mac[0] = 0x02; cfg->mac[1] = 0x00; cfg->mac[2] = 0x00;
    cfg->mac[3] = 0x00; cfg->mac[4] = 0x00; cfg->mac[5] = 0x01;
    cfg->ip = htonl(0x0a000002);  // 10.0.0.2
    cfg->netmask = htonl(0xffffff00);  // 255.255.255.0
    cfg->gateway = htonl(0x0a000001);  // 10.0.0.1
    cfg->mtu = 1500;
    cfg->veth_fd = -1;
    cfg->debug = 0;
    cfg->backend = BACKEND_AF_PACKET;
    cfg->dpdk_args[0] = '\0';
    
    // Try JSON config file first (like LKL)
    const char *config_file = getenv("NETBSD_HIJACK_CONFIG_FILE");
    if (!config_file) {
        config_file = "netbsd-hijack.json";  // Default name
    }
    
    if (access(config_file, R_OK) == 0) {
        if (load_json_config(config_file, cfg) == 0) {
            if (cfg->debug) {
                fprintf(stderr, "[Shim] Loaded config from %s\n", config_file);
            }
        }
    }
    
    // Environment variable overrides (higher priority than JSON)
    if ((env = getenv("NETBSD_IF_NAME"))) {
        strncpy(cfg->if_name, env, sizeof(cfg->if_name) - 1);
    }
    if ((env = getenv("NETBSD_IF_MAC"))) {
        parse_mac(env, cfg->mac);
    }
    if ((env = getenv("NETBSD_IF_IP"))) {
        cfg->ip = parse_ip(env);
    }
    if ((env = getenv("NETBSD_IF_NETMASK"))) {
        cfg->netmask = parse_ip(env);
    }
    if ((env = getenv("NETBSD_VETH_FD"))) {
        cfg->veth_fd = atoi(env);
    }
    if ((env = getenv("NETBSD_SHIM_DEBUG"))) {
        cfg->debug = atoi(env);
    }
    
    if (cfg->debug) {
        g_debug = cfg->debug;
        g_backend = cfg->backend;
        SHIM_LOG("Config: backend=%s if=%s mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%s\n",
                cfg->backend == BACKEND_DPDK ? "DPDK" : "AF_PACKET",
                cfg->if_name, cfg->mac[0], cfg->mac[1], cfg->mac[2],
                cfg->mac[3], cfg->mac[4], cfg->mac[5], 
                inet_ntoa((struct in_addr){.s_addr = cfg->ip}));
        if (cfg->backend == BACKEND_DPDK) {
            SHIM_LOG("DPDK Args: %s\n", cfg->dpdk_args);
        }
    }
}

// Constructor: Initialize shim
__attribute__((constructor))
static void shim_init(void)
{
    // Initialize recursive+robust mutex to handle signal reentrancy and dead threads
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);  // Recover from dead owner
    pthread_mutex_init(&g_lock, &ma);
    pthread_mutexattr_destroy(&ma);

    // If RTC mode is requested via env, skip automatic initialization
    if (getenv("NETBSD_RTC_MODE")) {
        fprintf(stderr, "[Shim] RTC Mode requested, skipping auto-init\n");
        
        // Resolve symbols only
        real_socket = dlsym(RTLD_NEXT, "socket");
        real_close = dlsym(RTLD_NEXT, "close");
        real_read = dlsym(RTLD_NEXT, "read");
        real_write = dlsym(RTLD_NEXT, "write");
        real_poll = dlsym(RTLD_NEXT, "poll");
        real_bind = dlsym(RTLD_NEXT, "bind");
        real_listen = dlsym(RTLD_NEXT, "listen");
        real_accept = dlsym(RTLD_NEXT, "accept");
        real_connect = dlsym(RTLD_NEXT, "connect");
        real_send = dlsym(RTLD_NEXT, "send");
        real_recv = dlsym(RTLD_NEXT, "recv");
        real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
        real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
        real_fcntl = dlsym(RTLD_NEXT, "fcntl");
        real_ioctl = dlsym(RTLD_NEXT, "ioctl");
        real_select = dlsym(RTLD_NEXT, "select");
        real_sendto = dlsym(RTLD_NEXT, "sendto");
        real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
        real_shutdown = dlsym(RTLD_NEXT, "shutdown");
        real_getsockname = dlsym(RTLD_NEXT, "getsockname");
        real_getpeername = dlsym(RTLD_NEXT, "getpeername");
        real_pselect = dlsym(RTLD_NEXT, "pselect");
        real_ppoll = dlsym(RTLD_NEXT, "ppoll");
        
        g_rtc_mode = 1; // Mark as RTC mode
        g_initialized = 1; // Mark as initialized so get_shim_handle etc don't crash (though they need struct)
        // Actually, we shouldn't mark initialized until RTC init runs.
        // But if we return here, g_initialized stays 0.
        // Calls to socket() etc check g_initialized. If 0, they use real_socket.
        // This is exactly what we want until netbsd_init_rtc is called!
        return;
    }

    fprintf(stderr, "[Shim] Initializing...\n");
    
    // Resolve real libc functions
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_close = dlsym(RTLD_NEXT, "close");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_poll = dlsym(RTLD_NEXT, "poll");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_listen = dlsym(RTLD_NEXT, "listen");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    real_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    real_fcntl = dlsym(RTLD_NEXT, "fcntl");
    real_ioctl = dlsym(RTLD_NEXT, "ioctl");
    real_select = dlsym(RTLD_NEXT, "select");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_shutdown = dlsym(RTLD_NEXT, "shutdown");
    real_getsockname = dlsym(RTLD_NEXT, "getsockname");
    real_getpeername = dlsym(RTLD_NEXT, "getpeername");
    real_pselect = dlsym(RTLD_NEXT, "pselect");
    real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    
    if (!real_socket || !real_close || !real_read || !real_write || !real_poll || !real_fcntl || !real_select || !real_sendto || !real_recvfrom || !real_shutdown || !real_getsockname || !real_getpeername || !real_pselect || !real_ppoll) {
        fprintf(stderr, "[Shim] ERROR: Failed to resolve libc functions\n");
        return;
    }

    g_initialized = 1;
    
    // Load configuration
    struct shim_config cfg;
    load_config(&cfg);
    g_debug = cfg.debug;
    g_backend = cfg.backend;
    
    // Initialize NetBSD stack
    SHIM_LOG("Initializing NetBSD stack...\n");
    netbsd_init();
    SHIM_LOG("NetBSD stack initialized\n");
    
    // Initialize FD table (redundant, already in netbsd_init, but harmless)
    // fd_table_init();
    
    // Use pre-opened FD if provided (Docker/container pattern)
    if (cfg.veth_fd >= 0) {
        g_veth_fd = cfg.veth_fd;
        fprintf(stderr, "[Shim] Using pre-opened veth FD: %d\n", g_veth_fd);
    } else {
        // Create virtual interface
        if (cfg.if_name[0]) {
            SHIM_LOG("Creating virtual interface %s...\n", cfg.if_name);
            g_vif = virt_if_create(cfg.if_name);
            if (!g_vif) {
                fprintf(stderr, "[Shim] ERROR: Failed to create %s\n", cfg.if_name);
                return;
            }
            SHIM_LOG("Virtual interface created\n");
            
            if (cfg.backend == BACKEND_AF_PACKET) {
                // Attach with configured MAC
                SHIM_LOG("Attaching interface with MAC...\n");
                if (virt_if_attach(g_vif, cfg.mac) < 0) {
                    fprintf(stderr, "[Shim] ERROR: Failed to attach veth\n");
                    return;
                }
                SHIM_LOG("Interface attached\n");

                // Configure IP from config
                uint32_t mask_host = ntohl(cfg.netmask);
                int prefix_len = __builtin_popcount(mask_host);
                if (virt_if_add_addr(g_vif, &cfg.ip, prefix_len, 1) < 0) {
                    fprintf(stderr, "[Shim] ERROR: Failed to set IP\n");
                    return;
                }
                
                // Setup AF_PACKET socket for external network I/O
                g_af_packet_fd = setup_af_packet(cfg.if_name);
                if (g_af_packet_fd < 0) {
                    fprintf(stderr, "[Shim] WARNING: Failed to setup AF_PACKET, continuing without external network\n");
                } else {
                    // Register packet output callback
                    virt_if_register_callbacks(g_vif, shim_packet_output, NULL);
                    g_veth_fd = g_af_packet_fd;
                }
            } else if (cfg.backend == BACKEND_DPDK) {
#ifdef USE_DPDK
                extern int dpdk_init(int argc, char **argv);
                extern void dpdk_set_virt_if(struct virt_interface *vif);
                extern int gen_if_output(void *m, long unsigned int total, void *arg);
                extern struct rte_ether_addr dpdk_port_addr;
                extern int dpdk_wait_link_up(int timeout_ms);
                extern void logger_init(void);
                
                // Initialize logger for DPDK LOG_INFO/LOG_ERROR calls
                logger_init();

                fprintf(stderr, "[Shim] DPDK backend selected, parsing args...\n");
                
                // Split dpdk_args into argc/argv
                char *args_dup = strdup(cfg.dpdk_args);
                char *argv[64];
                int argc = 0;
                argv[argc++] = "libnetbsdshim";
                char *token = strtok(args_dup, " ");
                while (token && argc < 63) {
                    argv[argc++] = token;
                    token = strtok(NULL, " ");
                }
                argv[argc] = NULL;

                fprintf(stderr, "[Shim] Calling dpdk_init with %d args...\n", argc);
                // Initialize DPDK
                int dpdk_ret = dpdk_init(argc, argv);
                fprintf(stderr, "[Shim] dpdk_init returned %d\n", dpdk_ret);
                if (dpdk_ret < 0) {
                    fprintf(stderr, "[Shim] ERROR: DPDK initialization failed\n");
                    free(args_dup);
                    return;
                }
                free(args_dup);
                fprintf(stderr, "[Shim] DPDK initialized successfully\n");
                
                // For memif, wait for the link to come up (client connecting to server)
                fprintf(stderr, "[Shim] Waiting for link up...\n");
                dpdk_wait_link_up(2000); // Wait up to 2 seconds for link
                fprintf(stderr, "[Shim] Link wait complete\n");

                // Re-attach with DPDK port MAC
                fprintf(stderr, "[Shim] Re-attaching interface with DPDK MAC...\n");
                virt_if_attach(g_vif, (const uint8_t *)&dpdk_port_addr);
                fprintf(stderr, "[Shim] Interface re-attached\n");
                
                // Configure IP from config
                uint32_t mask_host = ntohl(cfg.netmask);
                int prefix_len = __builtin_popcount(mask_host);

                struct in_addr ina;
                ina.s_addr = cfg.ip;
                fprintf(stderr, "[Shim] Adding IP %s (DPDK)\n", inet_ntoa(ina));
                if (virt_if_add_addr(g_vif, &cfg.ip, prefix_len, 1) < 0) {
                    fprintf(stderr, "[Shim] ERROR: Failed to set IP (DPDK)\n");
                    return;
                }
                fprintf(stderr, "[Shim] IP added\n");

                fprintf(stderr, "[Shim] Setting up DPDK callbacks...\n");
                dpdk_set_virt_if(g_vif);
                virt_if_register_callbacks(g_vif, gen_if_output, NULL);
                g_veth_fd = -1; // DPDK is polling-only
                fprintf(stderr, "[Shim] DPDK setup complete\n");
#else
                fprintf(stderr, "[Shim] ERROR: DPDK backend requested but not built into shim\n");
                return;
#endif
            }
            
            // Get veth FD for polling (will be AF_PACKET FD if available)
            if (g_veth_fd < 0) {
                g_veth_fd = virt_if_get_fd();
                if (g_veth_fd < 0) {
                    fprintf(stderr, "[Shim] WARNING: virt_if_get_fd() returned %d\n", g_veth_fd);
                }
            }
        }
    }
    
    // Create timer FD for 10ms periodic timer (NetBSD stack requirement)
    g_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (g_timer_fd < 0) {
        fprintf(stderr, "[Shim] ERROR: Failed to create timer FD\n");
        return;
    }
    
    struct itimerspec timer_spec = {
        .it_interval = { .tv_sec = 0, .tv_nsec = 1000000 },  // 1ms (optimized from 10ms)
        .it_value = { .tv_sec = 0, .tv_nsec = 1000000 }
    };
    if (timerfd_settime(g_timer_fd, 0, &timer_spec, NULL) < 0) {
        fprintf(stderr, "[Shim] ERROR: Failed to set timer\n");
        return;
    }
    
    // Only spawn background thread if NOT in RTC mode
    if (!g_rtc_mode) {
        g_running = 1;
        if (pthread_create(&g_stack_thread, NULL, stack_thread_func, NULL) != 0) {
            fprintf(stderr, "[Shim] ERROR: Failed to create background thread\n");
            return;
        }
        SHIM_LOG("Initialized successfully (Background Thread, veth_fd=%d, timer_fd=%d)\n", 
            g_veth_fd, g_timer_fd);
    } else {
        // RTC mode: Manual driving
        g_running = 1; // Mark as active
        SHIM_LOG("Initialized successfully (RTC Mode, veth_fd=%d, timer_fd=%d)\n", 
            g_veth_fd, g_timer_fd);
    }
}

// Destructor: Cleanup shim
__attribute__((destructor))
static void shim_cleanup(void)
{
    if (!g_initialized) return;
    
    fprintf(stderr, "[Shim] Cleaning up...\n");
    g_running = 0;
    pthread_join(g_stack_thread, NULL);
    
    if (g_timer_fd >= 0) {
        real_close(g_timer_fd);
    }
    
    // Flush any pending TX packets
    flush_tx_queue();
    
    fprintf(stderr, "[Shim] Cleanup complete\n");
}

// Background thread: Drive NetBSD stack
static void* stack_thread_func(void* arg)
{
    struct pollfd pfds[2];
    int nfds = 0;
    
    if (g_veth_fd >= 0) {
        pfds[nfds].fd = g_veth_fd;
        pfds[nfds].events = POLLIN;
        nfds++;
    }
    
    pfds[nfds].fd = g_timer_fd;
    pfds[nfds].events = POLLIN;
    nfds++;
    
    SHIM_LOG("Background thread started\n");
    
    while (g_running) {
        // For DPDK backend, use non-blocking poll since dpdk_read must spin
        int timeout = (g_backend == BACKEND_DPDK) ? 0 : -1;
        
        int ret = real_poll(pfds, nfds, timeout);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        // Process stack with lock held
        lock_robust();
        drive_stack();
        pthread_mutex_unlock(&g_lock);
    }
    
    SHIM_LOG("Background thread exiting\n");
    return NULL;
}

// Drive the NetBSD stack (must be called with g_lock held)
// Returns number of packets/events processed
static int drive_stack(void)
{
    int events = 0;
    
    // Read timer to clear expiration (non-blocking check)
    // In RTC mode, or normal mode, this drives the hardclock
    if (g_timer_fd >= 0) {
        struct pollfd pfd = { .fd = g_timer_fd, .events = POLLIN };
        if (real_poll(&pfd, 1, 0) > 0) {
            uint64_t expirations;
            if (real_read(g_timer_fd, &expirations, sizeof(expirations)) > 0) {
                // Call hardclock for each expiration (usually 1)
                for (uint64_t i = 0; i < expirations; i++) {
                    user_hardclock();
                }
                events++;
            }
        }
    }

#ifdef USE_DPDK
    if (g_backend == BACKEND_DPDK) {
        extern void dpdk_read(void);
        // dpdk_read (rx_burst) doesn't easily return count, but we assume it does work
        dpdk_read();
        events++; 
    }
#endif
    
    // Process ALL incoming packets from AF_PACKET socket using recvmmsg
    // (MMAP RX not working - reverting to syscall-based approach)
    if (g_af_packet_fd >= 0 && g_vif) {
        #define RX_BATCH 64
        static struct mmsghdr msgs[RX_BATCH];
        static struct iovec iovs[RX_BATCH];
        static char bufs[RX_BATCH][2048];
        static struct sockaddr_ll sas[RX_BATCH];
        static int initialized = 0;
        
        if (!initialized) {
            for (int i = 0; i < RX_BATCH; i++) {
                iovs[i].iov_base = bufs[i];
                iovs[i].iov_len = sizeof(bufs[i]);
                msgs[i].msg_hdr.msg_iov = &iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_hdr.msg_name = &sas[i];
                msgs[i].msg_hdr.msg_namelen = sizeof(sas[i]);
            }
            initialized = 1;
        }
        
        int pkts_processed = 0;
        while (pkts_processed < 512) { // Limit burst
            int n = recvmmsg(g_af_packet_fd, msgs, RX_BATCH, MSG_DONTWAIT, NULL);
            if (n < 0) {
                 if (errno != EAGAIN && errno != EWOULDBLOCK) {
                      SHIM_LOG("recvmmsg failed: %d (%s)\n", errno, strerror(errno));
                 }
                 break;
            }
            if (n == 0) break;
            
            for (int i = 0; i < n; i++) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)&sas[i];
                if (sll->sll_pkttype == PACKET_OUTGOING) continue;
                
                if (g_debug) {
                    fprintf(stderr, "[Shim] RX: len=%u pkt_type=%u\n", 
                            msgs[i].msg_len, sll->sll_pkttype);
                }
                virt_if_input(g_vif, bufs[i], msgs[i].msg_len);
            }
            pkts_processed += n;
        }
        events += pkts_processed;
    }
    
    softint_run();
    softint_run();
    netbsd_process_event();
    
    
    flush_tx_queue(); // Flush any pending TX packets
    
    return events;
}

// NetBSD Tick (RTC Mode)
void netbsd_rtc_tick(void)
{
    // Need lock because user_hardclock modifies kernel structures
    lock_robust();
    user_hardclock();
    pthread_mutex_unlock(&g_lock);
}

// NetBSD Loop (RTC Mode)
int netbsd_rtc_loop(void)
{
    if (!g_running) return 0;
    
    lock_robust();
    int events = drive_stack();
    pthread_mutex_unlock(&g_lock);
    
    return events;
}

// NetBSD Init RTC (helper to call shim_init manually if needed, or re-use logic)
int netbsd_init_rtc(const char *if_name, const char *ip, const char *mac_str)
{
    // Force link of inetdomain (AF_INET support)
    // Force link of inetdomain (AF_INET support)
    struct domain; // Forward declare
    extern struct domain inetdomain;
    extern void domain_attach(struct domain *);
    extern struct domain *pffinddomain(int);
    
    static int rtc_initialized = 0;
    if (rtc_initialized) return 0;

    // If initialized but NOT RTC mode, that's an error
    if (g_initialized && !g_rtc_mode) {
         fprintf(stderr, "[Shim] Error: Already initialized in threaded mode\n");
         return -1;
    }
    
    // Initialize NetBSD stack
    netbsd_init(); 
    
    // Manual attach if linker set failed (workaround for EAFNOSUPPORT)
    if (pffinddomain(AF_INET) == NULL) {
        fprintf(stderr, "[Shim] INET domain not found via pffinddomain. Manually attaching...\n");
        domain_attach(&inetdomain);
        if (pffinddomain(AF_INET) != NULL) {
             fprintf(stderr, "[Shim] Manual attach successful!\n");
        } else {
             fprintf(stderr, "[Shim] Manual attach FAILED!\n");
        }
    } else {
        fprintf(stderr, "[Shim] INET domain FOUND via pffinddomain. No manual attach needed.\n");
    }
    
    // Set RTC mode BEFORE calling constructor logic (if we could)
    // But since we are calling this manually, we assume shim_init constructor 
    // was skipped via env var or we are doing it here.
    // If shim_init was skipped, g_initialized is 0.
    
    // Manually run init logic
    // 1. Resolve symbols (if not done)
    if (!real_socket) {
        // Force shim_init to run partially? 
        // We can't call constructor. We'll duplicate the symbol resolution or just rely on shim_init being smart.
        // Let's assume shim_init ran but returned early because of env var.
        // So symbols ARE resolved.
    }
    
    if (!real_socket) {
        fprintf(stderr, "[Shim] Error: Symbols not resolved. Did shim_init run?\n");
        return -1;
    }
    
    struct shim_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    
    // 1. Load from JSON/Env if available
    load_config(&cfg);
    
    // 2. Override with explicit args if provided
    if (if_name) strncpy(cfg.if_name, if_name, sizeof(cfg.if_name)-1);
    
    if (mac_str) {
        parse_mac(mac_str, cfg.mac);
    }
    
    if (ip) cfg.ip = parse_ip(ip);
    
    // Note: load_config sets defaults (backends, mtu, etc) if not in JSON.
    // If CLI args like IP are not provided (i.e. NULL), we rely on what load_config loaded.
    
    g_rtc_mode = 1;
    g_debug = 1; // Enable debug for RTC init
    
    // Call our initialization logic (we need to be careful not to conflict with shim_init)
    // Since we copied the logic into shim_init, and we can't easily call it.
    // We should refactor shim_init to call an internal init function.
    // BUT for now, let's just "fake" it by relying on the fact that if NETBSD_RTC_MODE is set,
    // shim_init returns early. So we need to put the init logic here OR into a shared function.
    // Shared function is better.
    
    // Creating shared init function would be best, but for now I'll implement just enough here.
    
    // Re-use logic:
    pthread_mutexattr_t ma;
    pthread_mutexattr_init(&ma);
    pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutexattr_setrobust(&ma, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&g_lock, &ma);
    pthread_mutexattr_destroy(&ma);
    
    fprintf(stderr, "[Shim] RTC Init: %s IP=%08x\n", cfg.if_name, cfg.ip);
    // netbsd_init(); // ALREADY CALLED AT STARTED
    
    // Init VETH/DPDK
    fprintf(stderr, "[Shim] Checking backend configuration (%d)...\n", cfg.backend);
    if (cfg.backend == BACKEND_AF_PACKET) {
        fprintf(stderr, "[Shim] Creating virt_if %s...\n", cfg.if_name);
        g_vif = virt_if_create(cfg.if_name);
        if (!g_vif) fprintf(stderr, "[Shim] virt_if_create failed!\n");
        else fprintf(stderr, "[Shim] virt_if_create success. Attaching...\n");
        
        virt_if_attach(g_vif, cfg.mac);
        uint32_t mask_host = ntohl(cfg.netmask);
        int prefix_len = __builtin_popcount(mask_host);
        virt_if_add_addr(g_vif, &cfg.ip, prefix_len, 1);
        g_af_packet_fd = setup_af_packet(cfg.if_name);
        g_veth_fd = g_af_packet_fd; // Fix: Initialize poll FD
        virt_if_register_callbacks(g_vif, shim_packet_output, NULL);
    } 
    #ifdef USE_DPDK
    else if (cfg.backend == BACKEND_DPDK) {
        extern int dpdk_init(int argc, char **argv);
        extern void dpdk_set_virt_if(struct virt_interface *vif);
        extern int gen_if_output(void *m, long unsigned int total, void *arg);
        extern void logger_init(void);
        logger_init();
        
        // Parse dpdk_args for EAL init
        int dpdk_argc = 0;
        char *dpdk_argv[32];
        char args_copy[256];
        strncpy(args_copy, cfg.dpdk_args, sizeof(args_copy)-1);
        
        char *token = strtok(args_copy, " ");
        dpdk_argv[dpdk_argc++] = "rtc_app"; // Program name
        while (token && dpdk_argc < 31) {
            dpdk_argv[dpdk_argc++] = token;
            token = strtok(NULL, " ");
        }
        dpdk_argv[dpdk_argc] = NULL;
        
        fprintf(stderr, "[Shim] Calling dpdk_init with %d args: ", dpdk_argc);
        for(int i=0; i<dpdk_argc; i++) fprintf(stderr, "%s ", dpdk_argv[i]);
        fprintf(stderr, "\n");
        
        dpdk_init(dpdk_argc, dpdk_argv);
        
        // Memif/DPDK interface creation
        g_vif = virt_if_create(cfg.if_name);
        
        // IMPORTANT: Attach interface to stack (sets up ARP, etc)
        virt_if_attach(g_vif, cfg.mac);
        
        dpdk_set_virt_if(g_vif);
        virt_if_register_callbacks(g_vif, gen_if_output, NULL);
        
        // Add IP
        virt_if_add_addr(g_vif, &cfg.ip, 24, 1);
    }
    #endif

    g_backend = cfg.backend;
    
    // Create timer FD for 1ms periodic timer (NetBSD stack requirement)
    g_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (g_timer_fd < 0) {
        fprintf(stderr, "[Shim] ERROR: Failed to create timer FD\n");
    } else {
        struct itimerspec timer_spec = {
            .it_interval = { .tv_sec = 0, .tv_nsec = 1000000 },  // 1ms
            .it_value = { .tv_sec = 0, .tv_nsec = 1000000 }
        };
        if (timerfd_settime(g_timer_fd, 0, &timer_spec, NULL) < 0) {
            fprintf(stderr, "[Shim] ERROR: Failed to set timer\n");
        }
    }
    
    g_debug = 0; // Disable debug for perf
    
    g_initialized = 1;
    g_running = 1;
    rtc_initialized = 1;
    return 0;
}

// Inline driving (opportunistic, non-blocking)
static void drive_stack_inline(void)
{
    if (trylock_robust() == 0) {
        drive_stack();
        pthread_mutex_unlock(&g_lock);
    }
    // If lock fails, background thread is processing - skip
}

// Socket interceptor: Create NetBSD TCP socket
int socket(int domain, int type, int protocol)
{
    if (!g_initialized || !real_socket) {
        errno = ENOSYS;
        return -1;
    }
    
    // Only intercept AF_INET/AF_INET6 TCP sockets
    if ((domain != AF_INET && domain != AF_INET6) || type != SOCK_STREAM) {
        return real_socket(domain, type, protocol);
    }
    
    fprintf(stderr, "[Shim] socket(domain=%d, type=%d, protocol=%d)\n", domain, type, protocol);
    
    // Allocate NetBSD handle
    struct netbsd_handle *nh = (struct netbsd_handle*)malloc(sizeof(struct netbsd_handle));
    if (!nh) {
        fprintf(stderr, "[Shim] socket() failed: malloc failed\n");
        errno = ENOMEM;
        return -1;
    }
    memset(nh, 0, sizeof(struct netbsd_handle));
    nh->is_ipv4 = (domain == AF_INET) ? 1 : 0;
    nh->proto = PROTO_TCP;  // We only intercept SOCK_STREAM
    
    // Create NetBSD socket
    lock_robust();
    int ret = netbsd_socket(nh);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        int err = translate_netbsd_errno(-ret);
        fprintf(stderr, "[Shim] socket() failed: netbsd_socket returned %d (mapped to %d)\n", ret, err);
        free(nh);
        errno = err;
        return -1;
    }
    
    // Allocate internal FD (0-65535)
    int internal_fd = u_fd_alloc(nh);
    if (internal_fd < 0) {
        fprintf(stderr, "[Shim] socket() failed: no FDs available\n");
        lock_robust();
        netbsd_close(nh);
        pthread_mutex_unlock(&g_lock);
        errno = EMFILE;
        return -1;
    }
    
    // Return application FD (internal + offset shim)
    SHIM_LOG("socket() = %d (internal_fd=%d)\n", internal_fd + SHIM_FD_OFFSET, internal_fd);
    return internal_fd + SHIM_FD_OFFSET;
}

// Close interceptor: Free NetBSD socket and FD
int close(int fd)
{
    if (!g_initialized || !real_close) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        // Not a NetBSD socket, pass through to real close
        return real_close(fd);
    }
    
    SHIM_LOG("close(%d) (internal_fd=%d)\n", fd, fd - SHIM_FD_OFFSET);
    
    // Close NetBSD socket
    lock_robust();
    netbsd_close(nh);
    pthread_mutex_unlock(&g_lock);
    
    // Free internal FD
    u_fd_free(fd - SHIM_FD_OFFSET);
    
    return 0;
}

// Bind interceptor
int bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!g_initialized || !real_bind) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_bind(fd, addr, addrlen);
    }
    
    SHIM_LOG("bind(%d)\n", fd);
    
    lock_robust();
    int ret = netbsd_bind(nh, addr);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = translate_netbsd_errno(ret < 0 ? -ret : ret);
        return -1;
    }
    return 0;
}

// Listen interceptor
int listen(int fd, int backlog)
{
    if (!g_initialized || !real_listen) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_listen(fd, backlog);
    }
    
    SHIM_LOG("listen(%d, %d)\n", fd, backlog);
    
    lock_robust();
    int ret = netbsd_listen(nh, backlog);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = translate_netbsd_errno(ret < 0 ? -ret : ret);
        return -1;
    }
    return 0;
}

// Accept interceptor
int accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (!g_initialized || !real_accept) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_accept(fd, addr, addrlen);
    }
    
    SHIM_LOG("accept(%d)\n", fd);
    
    // Allocate handle for accepted socket
    struct netbsd_handle *nh_client = (struct netbsd_handle*)malloc(sizeof(struct netbsd_handle));
    if (!nh_client) {
        errno = ENOMEM;
        return -1;
    }
    memset(nh_client, 0, sizeof(struct netbsd_handle));
    
    // Try accept in a loop, driving stack while waiting
    while (1) {
        lock_robust();
        int ret = netbsd_accept(nh, nh_client);
        int is_nb = netbsd_is_nonblocking(nh);
        pthread_mutex_unlock(&g_lock);
        
        // netbsd_accept returns 0 on success, or positive NetBSD errno on failure
        if (ret == 0) {
            // Success - allocate FD
            int client_internal_fd = u_fd_alloc(nh_client);
            if (client_internal_fd < 0) {
                lock_robust();
                netbsd_close(nh_client);
                pthread_mutex_unlock(&g_lock);
                free(nh_client);
                errno = EMFILE;
                return -1;
            }
            
            // Fill in addr if provided
            if (addr && addrlen) {
                struct sockaddr_storage ss;
                socklen_t slen = sizeof(ss);
                lock_robust();
                int gp_ret = netbsd_getpeername(nh_client, (struct sockaddr *)&ss, &slen);
                pthread_mutex_unlock(&g_lock);
                
                if (gp_ret == 0) {
                    socklen_t copy_len = (*addrlen < slen) ? *addrlen : slen;
                    memcpy(addr, &ss, copy_len);
                    *addrlen = slen;
                }
            }

            int client_app_fd = client_internal_fd + SHIM_FD_OFFSET;
            SHIM_LOG("accept() = %d (internal_fd=%d)\n", client_app_fd, client_internal_fd);
            return client_app_fd;
        }
        
        int err = translate_netbsd_errno(ret);
        if (err != EAGAIN && err != EWOULDBLOCK) {
            fprintf(stderr, "[Shim] accept error: ret=%d (mapped to %d)\n", ret, err);
            free(nh_client);
            errno = err;
            return -1;
        }
        
        if (is_nb) {
            free(nh_client);
            errno = EAGAIN;
            return -1;
        }
        
        // EAGAIN - poll on veth + timer FD and drive stack
        struct pollfd pfds[2];
        pfds[0].fd = g_veth_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = g_timer_fd;
        pfds[1].events = POLLIN;
        
        real_poll(pfds, 2, 100);  // 100ms timeout for accept
        
        // ALWAYS drive the stack if we are blocking, even if poll didn't trigger,
        // to handle timers and internal state.
        lock_robust();
        drive_stack();
        pthread_mutex_unlock(&g_lock);
    }
}

// Read interceptor
ssize_t read(int fd, void *buf, size_t count)
{
    if (!g_initialized || !real_read) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_read(fd, buf, count);
    }
    
    struct iovec iov = { .iov_base = buf, .iov_len = count };
    
    // Try read in a loop, driving stack while waiting
    while (1) {
        lock_robust();
        int ret = netbsd_read(nh, &iov, 1);
        int is_nb = netbsd_is_nonblocking(nh);
        pthread_mutex_unlock(&g_lock);
        
        if (ret >= 0) {
            if (ret > 0) SHIM_LOG("read(%d) = %d bytes\n", fd, ret);
            return ret;
        }
        
        int err = translate_netbsd_errno(-ret);
        if (err != EAGAIN && err != EWOULDBLOCK) {
            errno = err;
            return -1;
        }
        
        if (is_nb) {
            errno = EAGAIN;
            return -1;
        }
        
        // Blocking: poll on veth + timer FD and drive stack
        struct pollfd pfds[2];
        pfds[0].fd = g_veth_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = g_timer_fd;
        pfds[1].events = POLLIN;
        
        real_poll(pfds, 2, 1);  // 1ms timeout (optimized from 10ms)
        lock_robust();
        drive_stack();
        pthread_mutex_unlock(&g_lock);
    }
}

// Write interceptor
ssize_t write(int fd, const void *buf, size_t count)
{
    if (!g_initialized || !real_write) {
        errno = ENOSYS;
        return -1;
    }
    
    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_write(fd, buf, count);
    }
    
    struct iovec iov = { .iov_base = (void*)buf, .iov_len = count };
    // Use netbsd_send for simple write
    SHIM_LOG("write(%d) called len=%zu\n", fd, count);
    
    // Try write in a loop, driving stack while waiting
    while (1) {
        lock_robust();
        
        // Debug: check connection before write
        // int is_connected_pre = netbsd_is_connected(nh);
        
        int ret = netbsd_write(nh, &iov, 1);
        int is_nb = netbsd_is_nonblocking(nh);
        pthread_mutex_unlock(&g_lock);
        
        // SHIM_LOG("RAW netbsd_write ret=%d errno=%d\n", ret, errno);
        
        if (ret >= 0) {
            if (ret > 0) {
                 long sb_cc=0, sb_hiwat=0;
                 int state=0, so_error=0;
                 short sb_flags=0;
                 netbsd_get_debug_info(nh, &sb_cc, &sb_hiwat, &state, &so_error, &sb_flags);
                 SHIM_LOG("write(%d) = %d bytes. nh=%p, so=%p, State=0x%x, Flags=0x%x\n", fd, ret, nh, nh->so, state, sb_flags);
            } else {
                 SHIM_LOG("write(%d) returned 0 bytes! nh=%p, so=%p\n", fd, nh, nh->so);
            }
            return ret;
        }
        
        int err = translate_netbsd_errno(-ret);
        if (err != EAGAIN && err != EWOULDBLOCK) {
            // Workaround: netbsd_write returns ENOTCONN if socket state is corrupted or regression happens.
            // Treat ENOTCONN as EAGAIN to allow loop to fix the state.
            if (err == 107 || err == 57) {
                 SHIM_LOG("write(%d) ENOTCONN -> EAGAIN (Workaround)\n", fd);
                 err = EAGAIN;
                 errno = EAGAIN;
            }
        
            if (err != EAGAIN && err != EWOULDBLOCK) {
                fprintf(stderr, "[Shim] write(%d) failed: ret=%d, errno=%d\n", fd, ret, err);
                errno = err;
                return -1;
            } else {
                // EAGAIN loop debug
                static int loop_cnt = 0;
                if (loop_cnt++ % 1000 == 0) {
                     long sb_cc=0, sb_hiwat=0;
                     int state=0, so_error=0;
                     short sb_flags=0;
                     netbsd_get_debug_info(nh, &sb_cc, &sb_hiwat, &state, &so_error, &sb_flags);
                     SHIM_LOG("write(%d) EAGAIN. loop=%d, nh=%p, so=%p, sb_cc=%ld, sb_hiwat=%ld, state=0x%x, flags=0x%x, error=%d\n", 
                             fd, loop_cnt, nh, nh->so, sb_cc, sb_hiwat, state, sb_flags, so_error);
                             
                     // Workaround: If stuck in CONNECTING (0x4) OR DISCONNECTED (0) OR SB_LOCK set with empty buffer
                     // We force state to CONNECTED if buffer is empty
                     if ((state == 0x4 || state == 0 || (sb_flags & 0x01)) && sb_cc == 0) {
                         netbsd_force_connected(nh);
                     }
                }
            }
        }

        
        if (is_nb) {
            errno = EAGAIN;
            return -1;
        }
        
        // Blocking: poll on veth + timer FD and drive stack
        struct pollfd pfds[2];
        pfds[0].fd = g_veth_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = g_timer_fd;
        pfds[1].events = POLLIN;
        
        real_poll(pfds, 2, 1);  // 1ms timeout (optimized from 10ms)
        drive_stack_inline(); // Use non-blocking version to avoid deadlock
    }
}

// connect() interceptor
int connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!g_initialized || !real_connect) {
        errno = ENOSYS;
        return -1;
    }

    struct netbsd_handle *nh = get_shim_handle(fd);
    if (!nh) {
        return real_connect(fd, addr, addrlen);
    }
    
    SHIM_LOG("connect(%d)\n", fd);
    
    // Try connect in a loop (NetBSD connect is non-blocking internally or needs stack driving)
    while (1) {
        lock_robust();
        int ret = netbsd_connect(nh, (struct sockaddr *)addr);
        int is_nb = netbsd_is_nonblocking(nh);
        int is_connecting = netbsd_is_connecting(nh);
        int is_connected = netbsd_is_connected(nh);
        int so_error = netbsd_socket_error(nh);
        pthread_mutex_unlock(&g_lock);
        
        // Debug logging for connect analysis
        SHIM_LOG("netbsd_connect(%d) returned %d. is_nb=%d is_connecting=%d is_connected=%d so_error=%d\n", 
                fd, ret, is_nb, is_connecting, is_connected, so_error);

        if (so_error) {
            errno = translate_netbsd_errno(so_error);
            return -1;
        }

        if (ret == 0) {
            if (is_connected) return 0;
            if (is_nb && is_connecting) {
               errno = EINPROGRESS;
               return -1;
            }
            // If blocking and still connecting, we must wait
        } else {
            int err = translate_netbsd_errno(ret < 0 ? -ret : ret);
            if (err == EISCONN || err == 106 || err == 56) return 0;
            if (is_nb && (err == EINPROGRESS || err == EALREADY || err == EAGAIN)) {
                errno = EINPROGRESS;
                return -1;
            }
            if (err != EINPROGRESS && err != EALREADY && err != EAGAIN) {
                errno = err;
                return -1;
            }
        }
        
        // Need to wait and drive stack
        struct pollfd pfds[2];
        pfds[0].fd = g_veth_fd;
        pfds[0].events = POLLIN;
        pfds[1].fd = g_timer_fd;
        pfds[1].events = POLLIN;
        real_poll(pfds, 2, 5); // Short wait
        
        drive_stack_inline();
    }
}

// NetBSD Socket Options
#define NB_SOL_SOCKET   0xffff
#define NB_SO_DEBUG     0x0001
#define NB_SO_REUSEADDR 0x0004
#define NB_SO_KEEPALIVE 0x0008
#define NB_SO_ERROR     0x1007
#define NB_SO_SNDBUF    0x1001
#define NB_SO_RCVBUF    0x1002

static void translate_sockopt(int level, int optname, int *nb_level, int *nb_optname)
{
    *nb_level = level;
    *nb_optname = optname;

    if (level == SOL_SOCKET) {
        *nb_level = NB_SOL_SOCKET;
        switch (optname) {
            case SO_DEBUG: *nb_optname = NB_SO_DEBUG; break;
            case SO_REUSEADDR: *nb_optname = NB_SO_REUSEADDR; break;
            case SO_KEEPALIVE: *nb_optname = NB_SO_KEEPALIVE; break;
            case SO_ERROR: *nb_optname = NB_SO_ERROR; break;
            case SO_SNDBUF: *nb_optname = NB_SO_SNDBUF; break;
            case SO_RCVBUF: *nb_optname = NB_SO_RCVBUF; break;
            // Add others as needed
            default: break; 
        }
    }
    // TCP options usually match (TCP_NODELAY=1 on both)
}

// getsockopt() interceptor
int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)
{
    if (!g_initialized || !real_getsockopt) {
        errno = ENOSYS;
        return -1;
    }

    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_getsockopt(fd, level, optname, optval, optlen);
    }

    int nb_level, nb_optname;
    translate_sockopt(level, optname, &nb_level, &nb_optname);

    // Intercept TCP_INFO to prevent garbage stats and ENOMSG errors
    // Linux iperf3 expects TCP_INFO (11) to work. NetBSD might return ENOPROTOOPT or similar.
    // Shim it by returning 0 and zeroing the buffer.
    if (level == 6 /* SOL_TCP */ && optname == 11 /* TCP_INFO */) {
        if (optval && optlen) {
            memset(optval, 0, *optlen);
        }
        return 0;
    }

    // Intercept TCP_CONGESTION (13) which iperf3 uses to check algorithm
    if (level == 6 /* SOL_TCP */ && optname == 13 /* TCP_CONGESTION */) {
        if (optval && optlen && *optlen > 0) {
            // Return "cubic" or "reno"
            const char *algo = "reno";
            size_t algo_len = strlen(algo) + 1;
            if (*optlen >= algo_len) {
                strcpy((char*)optval, algo);
                *optlen = algo_len;
            } else {
                 strncpy((char*)optval, algo, *optlen);
                 ((char*)optval)[*optlen - 1] = '\0';
            }
        }
        return 0;
    }

    SHIM_LOG("getsockopt(%d, level=%d, optname=%d) -> (%d, %d)\n", 
            fd, level, optname, nb_level, nb_optname);
    
    lock_robust();
    int ret = netbsd_getsockopt(nh, nb_level, nb_optname, optval, optlen);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = translate_netbsd_errno(ret);
        return -1;
    }
    // Intercept SO_ERROR to translate the socket error code provided in optval
    if (level == SOL_SOCKET && optname == SO_ERROR) {
        if (optval && optlen && *optlen >= sizeof(int)) {
            int *err_ptr = (int*)optval;
            int nb_err = *err_ptr;
            int lx_err;
            
            // Special case: EISCONN (56) in SO_ERROR means connected, treat as success (0)
            if (nb_err == 56) {
                lx_err = 0;
            } else {
                lx_err = translate_netbsd_errno(nb_err);
            }

            if (nb_err != lx_err) {
                 *err_ptr = lx_err;
                 SHIM_LOG("getsockopt(SO_ERROR) translated %d -> %d\n", nb_err, lx_err);
            }
        }
    }

    return 0;
}

// setsockopt() interceptor
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (!g_initialized || !real_setsockopt) {
        errno = ENOSYS;
        return -1;
    }

    struct netbsd_handle *nh = get_shim_handle(fd);
    
    if (!nh) {
        return real_setsockopt(fd, level, optname, optval, optlen);
    }

    int nb_level, nb_optname;
    translate_sockopt(level, optname, &nb_level, &nb_optname);

    SHIM_LOG("setsockopt(%d, level=%d, optname=%d) -> (%d, %d)\n", 
            fd, level, optname, nb_level, nb_optname);
    
    lock_robust();
    int ret = netbsd_setsockopt(nh, nb_level, nb_optname, optval, optlen);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = translate_netbsd_errno(ret);
        return -1;
    }
    return 0;
}

// Shared fcntl logic
// Shared fcntl logic helper
static int shim_do_fcntl(int fd, int cmd, va_list ap)
{
    if (!g_initialized || !real_fcntl) {
        errno = ENOSYS;
        return -1;
    }

    struct netbsd_handle *nh = get_shim_handle(fd);
    
    // Extract arg for consistency with real_fcntl
    long arg = va_arg(ap, long);

    if (!nh) {
        return real_fcntl(fd, cmd, arg);
    }

    SHIM_LOG("fcntl(%d, cmd=%d)\n", fd, cmd);

    if (cmd == F_SETFL) {
        if (arg & O_NONBLOCK) {
            lock_robust();
            netbsd_set_nonblocking(nh, 1);
            pthread_mutex_unlock(&g_lock);
        } else {
            lock_robust();
            netbsd_set_nonblocking(nh, 0);
            pthread_mutex_unlock(&g_lock);
        }
        return 0;
    } else if (cmd == F_GETFL) {
        lock_robust();
        int is_nb = netbsd_is_nonblocking(nh);
        pthread_mutex_unlock(&g_lock);
        return is_nb ? O_NONBLOCK : 0;
    }

    return 0;
}

// Interceptor for legacy fcntl
// We use a different C name 'shim_fcntl_legacy' but export it as 'fcntl' symbol
// using __asm__ to avoid collision with the header's 'fcntl' -> 'fcntl64' rename.
__attribute__((visibility("default"), used))
int shim_fcntl_legacy(int fd, int cmd, ...) __asm__("fcntl");

int shim_fcntl_legacy(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    int ret = shim_do_fcntl(fd, cmd, ap);
    va_end(ap);
    return ret;
}

// Interceptor for fcntl64
#undef fcntl64
__attribute__((visibility("default"), used))
int fcntl64(int fd, int cmd, ...)
{
    va_list ap;
    va_start(ap, cmd);
    int ret = shim_do_fcntl(fd, cmd, ap);
    va_end(ap);
    return ret;
}

// ioctl() interceptor
__attribute__((visibility("default"), used))
int ioctl(int fd, unsigned long request, ...)
{
    if (!g_initialized || !real_ioctl) {
        errno = ENOSYS;
        return -1;
    }

    struct netbsd_handle *nh = get_shim_handle(fd);
    
    va_list args;
    va_start(args, request);
    void *argp = va_arg(args, void *);
    va_end(args);

    if (!nh) {
        return real_ioctl(fd, request, argp);
    }

    SHIM_LOG("ioctl(%d, request=%lu)\n", fd, request);

    if (request == FIONBIO) {
        int nb = *(int *)argp;
        lock_robust();
        netbsd_set_nonblocking(nh, nb);
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    return 0;
}



// shutdown() interceptor
__attribute__((visibility("default"), used))
int shutdown(int fd, int how)
{
    struct netbsd_handle *nh = get_shim_handle(fd);
    if (!nh) {
        if (!real_shutdown) real_shutdown = dlsym(RTLD_NEXT, "shutdown");
        return real_shutdown(fd, how);
    }
    
    lock_robust();
    int ret = netbsd_shutdown(nh, how);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

// getsockname() interceptor
__attribute__((visibility("default"), used))
int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct netbsd_handle *nh = get_shim_handle(fd);
    if (!nh) {
        if (!real_getsockname) real_getsockname = dlsym(RTLD_NEXT, "getsockname");
        return real_getsockname(fd, addr, addrlen);
    }
    
    lock_robust();
    int ret = netbsd_getsockname(nh, addr, addrlen);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

// getpeername() interceptor
__attribute__((visibility("default"), used))
int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    struct netbsd_handle *nh = get_shim_handle(fd);
    if (!nh) {
        if (!real_getpeername) real_getpeername = dlsym(RTLD_NEXT, "getpeername");
        return real_getpeername(fd, addr, addrlen);
    }
    
    lock_robust();
    int ret = netbsd_getpeername(nh, addr, addrlen);
    pthread_mutex_unlock(&g_lock);
    
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

// poll() interceptor - simplified version
static uint64_t get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// poll() interceptor - mixed FDs
__attribute__((visibility("default"), used))
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (!g_initialized || !real_poll) {
        errno = ENOSYS;
        return -1;
    }

    int rc = 0;
    int has_events = 0;
    int time_left = timeout;
    uint64_t start_time = get_time_ms();

    // Allocate temp array for real_poll (worst case size nfds)
    // In a production shim we might want to avoid malloc on hot path, but strict stack size limits apply.
    // For now, use malloc for simplicity with mixed sets.
    struct pollfd *linux_fds = NULL;
    int *linux_map = NULL; // Maps index in linux_fds back to original fds index
    
    if (nfds > 0) {
        linux_fds = malloc(sizeof(struct pollfd) * nfds);
        linux_map = malloc(sizeof(int) * nfds);
        if (!linux_fds || !linux_map) {
            free(linux_fds);
            free(linux_map);
            errno = ENOMEM;
            return -1;
        }
    }

    while (1) {
        has_events = 0;
        int linux_count = 0;
        
        // 1. Prepare Linux FDs for real_select/poll and check NetBSD FDs
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].fd < 0) continue; // Ignore negative FDs

            struct netbsd_handle *nh = get_shim_handle(fds[i].fd);

            if (nh) {
                // Check NetBSD socket
                lock_robust();
                // Note: We might want to pass more flags if needed, but for now map types directly
                // Assuming standard POLL* constants match (they usually do on Linux)
                int revents = netbsd_poll_check(nh, fds[i].events);
                pthread_mutex_unlock(&g_lock);

                // Debug log for NetBSD poll
                if (fds[i].events & (POLLIN|POLLOUT)) {
                     print_poll_events(fds[i].fd, fds[i].events, "[Shim] poll request:");
                     print_poll_events(fds[i].fd, revents, "[Shim] poll result:");
                }

                if (nh && nh->type != 0) { // NetBSD socket
                    // Debug: Log if polling NetBSD socket and returns 0 events but we expect data (e.g. FD > 500)
                    // The 'revents' variable is already defined and populated above.
                    // 'pfd' is not in scope, use 'fds[i]' instead.
                    
                    if (fds[i].fd == 502 || fds[i].fd == 503) {
                         static int trace_cnt = 0;
                         if (trace_cnt++ % 1000 == 0) {
                             long sb_cc=0;
                             netbsd_get_debug_info(nh, &sb_cc, NULL, NULL, NULL, NULL);
                             SHIM_LOG("POLL CHECK fd=%d events=0x%x revents=0x%x sb_cc=%ld\n", fds[i].fd, fds[i].events, revents, sb_cc);
                         }
                    }

                    if (revents == 0 && (fds[i].events & POLLIN) && fds[i].fd >= 500) {
                        static int poll_debug_cnt = 0;
                        if (poll_debug_cnt++ % 1000 == 0) {
                             long sb_cc=0;
                             netbsd_get_debug_info(nh, &sb_cc, NULL, NULL, NULL, NULL);
                             SHIM_LOG("poll(%d) ret=0. sb_cc=%ld\n", fds[i].fd, sb_cc);
                        }
                    }
                }

                if (revents) {
                    fds[i].revents = revents;
                    has_events++;
                } else {
                    fds[i].revents = 0;
                }
            } else {
                // Must be Linux FD
                linux_fds[linux_count].fd = fds[i].fd;
                linux_fds[linux_count].events = fds[i].events;
                linux_fds[linux_count].revents = 0;
                linux_map[linux_count] = i;
                linux_count++;
                fds[i].revents = 0; // Clear initially, will be updated from real_poll result
            }
        }

        // 2. Poll Linux FDs (non-blocking call)
        if (linux_count > 0) {
            int l_rc = real_poll(linux_fds, linux_count, 0); // Immediate return
            if (l_rc > 0) {
                for (int j = 0; j < linux_count; j++) {
                    if (linux_fds[j].revents) {
                        int orig_idx = linux_map[j];
                        fds[orig_idx].revents = linux_fds[j].revents;
                        has_events++;
                    }
                }
            } else if (l_rc < 0) {
                // Error in real_poll
                rc = -1;
                // If it's just one FD failing, finding which one is hard in bulk. 
                // But for standard errors like EBADF, usually fatal or specific.
                // We'll propagate errno.
                goto cleanup;
            }
        }

        // 3. Check termination conditions
        if (has_events) {
            rc = has_events;
            // fprintf(stderr, "[Shim] poll returning %d events\n", rc);
            goto cleanup;
        }

        if (timeout >= 0) {
            uint64_t now = get_time_ms();
            int elapsed = (int)(now - start_time);
            if (elapsed >= timeout) {
                rc = 0; // Timeout
                goto cleanup;
            }
            // Update time_left not strictly needed if we recalculate elapsed, 
            // but helpful for mental model.
        }

        // 4. Wait a bit before retrying
        // If we have a timeout, we should wait on g_veth_fd and g_timer_fd to wake up the stack
        if (timeout != 0) {
            struct pollfd pfds_internal[2];
            int internal_count = 0;
            if (g_veth_fd >= 0) {
                pfds_internal[internal_count].fd = g_veth_fd;
                pfds_internal[internal_count].events = POLLIN;
                internal_count++;
            }
            if (g_timer_fd >= 0) {
                pfds_internal[internal_count].fd = g_timer_fd;
                pfds_internal[internal_count].events = POLLIN;
                internal_count++;
            }
            
            // Wait for up to 10ms or until timeout
            int wait_ms = 10;
            if (timeout > 0) {
                uint64_t now = get_time_ms();
                int remaining = timeout - (int)(now - start_time);
                if (remaining < wait_ms) wait_ms = remaining > 0 ? remaining : 0;
            }
            
            if (internal_count > 0 && wait_ms > 0) {
                real_poll(pfds_internal, internal_count, wait_ms);
            } else if (wait_ms > 0) {
                usleep(wait_ms * 1000);
            }
        }

        drive_stack_inline();

        if (timeout == 0) {
            rc = 0; // Immediate return
            goto cleanup;
        }
    }

cleanup:
    free(linux_fds);
    free(linux_map);
    return rc;
}

// select() interceptor - implemented via poll()
__attribute__((visibility("default"), used))
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    if (!g_initialized || !real_select) {
        errno = ENOSYS;
        return -1;
    }
    // fprintf(stderr, "[Shim] select(nfds=%d) called\n", nfds);

    struct pollfd *pfds = NULL;
    int poll_nfds = 0;
    int rc = 0;
    int fd;

    // 1. Assist in determining how many pollfds we need
    // nfds is the highest FD + 1. We scan all sets up to nfds.
    // In practice, we only care about set bits.
    // However, allocating array of size nfds is safe but potentially large (up to 66560+).
    // We can iterate first to count set bits.
    int count = 0;
    for (fd = 0; fd < nfds; fd++) {
        if ((readfds && FD_ISSET(fd, readfds)) ||
            (writefds && FD_ISSET(fd, writefds)) ||
            (exceptfds && FD_ISSET(fd, exceptfds))) {
            count++;
        }
    }

    if (count > 0) {
        pfds = malloc(sizeof(struct pollfd) * count);
        if (!pfds) {
            errno = ENOMEM;
            return -1;
        }
    }

    // 2. Populate pollfds
    int i = 0;
    for (fd = 0; fd < nfds; fd++) {
        short events = 0;
        if (readfds && FD_ISSET(fd, readfds)) events |= POLLIN;
        if (writefds && FD_ISSET(fd, writefds)) events |= POLLOUT;
        if (exceptfds && FD_ISSET(fd, exceptfds)) events |= POLLPRI;

        if (events) {
            pfds[i].fd = fd;
            pfds[i].events = events;
            pfds[i].revents = 0;
            i++;
        }
    }
    poll_nfds = i;

    // 3. Clear the sets (select semantics)
    if (readfds) FD_ZERO(readfds);
    if (writefds) FD_ZERO(writefds);
    if (exceptfds) FD_ZERO(exceptfds);

    // 4. Call poll()
    int poll_timeout = -1;
    if (timeout) {
        poll_timeout = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    }

    int ret = poll(pfds, poll_nfds, poll_timeout);

    // 5. Update sets based on results
    if (ret > 0) {
        rc = 0;
        for (i = 0; i < poll_nfds; i++) {
            if (pfds[i].revents) {
                int f = pfds[i].fd;
                int added = 0;
                if ((pfds[i].revents & (POLLIN|POLLHUP|POLLERR)) && readfds) {
                    FD_SET(f, readfds);
                    added = 1;
                }
                if ((pfds[i].revents & (POLLOUT|POLLERR)) && writefds) {
                    FD_SET(f, writefds);
                    added = 1;
                }
                if ((pfds[i].revents & POLLPRI) && exceptfds) {
                    FD_SET(f, exceptfds);
                    added = 1;
                }
                if (added) rc++;
            }
        }
    } else if (ret == 0) {
        rc = 0; // Timeout
    } else {
        rc = -1; // Error (errno set by poll)
    }

    free(pfds);
    return rc;
}

// ppoll() interceptor
__attribute__((visibility("default"), used))
int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)
{
    // Ignore sigmask for now (atomic signal masking not supported by shim yet)
    int timeout = -1;
    if (tmo_p) {
        timeout = tmo_p->tv_sec * 1000 + tmo_p->tv_nsec / 1000000;
    }
    return poll(fds, nfds, timeout);
}

// pselect() interceptor
__attribute__((visibility("default"), used))
int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           const struct timespec *timeout, const sigset_t *sigmask)
{
    // Reuse select() logic but with timespec
    struct timeval tv;
    struct timeval *tvp = NULL;
    if (timeout) {
        tv.tv_sec = timeout->tv_sec;
        tv.tv_usec = timeout->tv_nsec / 1000;
        tvp = &tv;
    }
    // Ignore sigmask
    return select(nfds, readfds, writefds, exceptfds, tvp);
}

// epoll interceptors (Logging only for now)
#include <sys/epoll.h>

static int (*real_epoll_create)(int) = NULL;
static int (*real_epoll_create1)(int) = NULL;
static int (*real_epoll_ctl)(int, int, int, struct epoll_event *) = NULL;
static int (*real_epoll_wait)(int, struct epoll_event *, int, int) = NULL;

__attribute__((visibility("default"), used))
int epoll_create(int size) {
    if (!real_epoll_create) real_epoll_create = dlsym(RTLD_NEXT, "epoll_create");
    int ret = real_epoll_create(size);
    fprintf(stderr, "[Shim] epoll_create(%d) = %d\n", size, ret);
    return ret;
}

__attribute__((visibility("default"), used))
int epoll_create1(int flags) {
    if (!real_epoll_create1) real_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
    int ret = real_epoll_create1(flags);
    fprintf(stderr, "[Shim] epoll_create1(%d) = %d\n", flags, ret);
    return ret;
}

__attribute__((visibility("default"), used))
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    if (!real_epoll_ctl) real_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
    int ret = real_epoll_ctl(epfd, op, fd, event);
    if (fd >= 500) {
        fprintf(stderr, "[Shim] epoll_ctl(epfd=%d, op=%d, fd=%d) = %d (errno=%d)\n", epfd, op, fd, ret, errno);
    }
    return ret;
}

__attribute__((visibility("default"), used))
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    if (!real_epoll_wait) real_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
    // fprintf(stderr, "[Shim] epoll_wait(epfd=%d, timeout=%d)\n", epfd, timeout);
    return real_epoll_wait(epfd, events, maxevents, timeout);
}

static int (*real_epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *) = NULL;

__attribute__((visibility("default"), used))
int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask) {
    if (!real_epoll_pwait) real_epoll_pwait = dlsym(RTLD_NEXT, "epoll_pwait");
    // fprintf(stderr, "[Shim] epoll_pwait(epfd=%d, timeout=%d)\n", epfd, timeout);
    return real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}



