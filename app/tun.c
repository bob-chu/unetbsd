#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include "u_if.h"

static int socket_fd;

static struct virt_interface *v_if;
int af_packet_input(void *data, long unsigned int len, void *arg);
int af_packet_output(void *data, long unsigned int len, void *arg);
int af_packet_output_m(void *data, long unsigned int len, void *arg);

void print_packet(unsigned char *buf, int len, bool dir)
{
    int i;
    printf("Packet: %s Length: %d\n", dir ? "IN" : "OUT", len);
    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n\n");
}

#define BUFFER_SIZE  1518
int open_af_packet()
{
    char *if_name = "veth1";
    unsigned char buffer[BUFFER_SIZE];
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int if_index;
    int recv_len;
    unsigned char dest_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    unsigned char src_mac[ETH_ALEN];


    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd == -1) {
        perror("socket() error");
        return -1;
    }

    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL) error");
        close(socket_fd);
        return -1;
    }
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL, O_NONBLOCK) error");
        close(socket_fd);
        return -1;
    }
    printf("AF_PACKET socket created successfully.\n");

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl(SIOCGIFINDEX) error");
        close(socket_fd);
        return -1;
    }
    if_index = ifr.ifr_ifindex;
    printf("Interface index for %s: %d\n", if_name, if_index);

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(socket_fd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl(SIOCGIFHWADDR) error");
        close(socket_fd);
        return -1;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    printf("Source MAC address for %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
            if_name, src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);


    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(socket_fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind() error");
        close(socket_fd);
        return -1;
    }
    printf("Socket bind to interface %s successfully.\n", if_name);

    /* create netbsd virtual interface */
    v_if = virt_if_create(if_name);
    virt_if_attach(v_if, src_mac);

    //virt_if_register_callbacks(v_if, af_packet_output, af_packet_input);
    virt_if_register_callbacks(v_if, af_packet_output_m, af_packet_input);

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
    return socket_fd;
}

void close_af_packet()
{
    if (socket_fd) {
        close(socket_fd);
    }
}

int af_packet_input(void *data, long unsigned int len, void *arg)
{
    print_packet((char *)data, len, true);
    virt_if_input(v_if, data, len);
    return 0;
}

int af_packet_output(void *data, long unsigned int len, void *arg)
{
    print_packet((char *)data, len, false);
    int bytes = write(socket_fd, (char *)data, len);
    if (bytes < 0) {
        printf("write socket error\n");
    }
    return 0;
}

int af_packet_output_m(void *m, long unsigned int len, void *arg)
{
#define MAX_OUT_MBUFS 8
    struct iovec iov[MAX_OUT_MBUFS];
    int i, total_len, count;
    char *data;

    //count = array_size(iov);
    count = sizeof(iov)/sizeof(iov[0]);

    total_len = netbsd_mbufvec(m, iov, &count);
    if (total_len == 0) {
        return -1;
    }
    char *data_ptr = malloc(total_len+1);
    if (!data_ptr) return -1;
    int offset = 0;

    for (i = 0; i < count; i++) {
        memcpy(data_ptr + offset, iov[i].iov_base, iov[i].iov_len);
        offset += iov[i].iov_len; 
    }
    print_packet((char *)data_ptr, total_len, false);
    int bytes = write(socket_fd, (char *)data_ptr, total_len);
    if (bytes < 0) {
        printf("write socket error\n");
    }
    free(data_ptr);
    return 0;
}

