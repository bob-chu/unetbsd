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
    char *if_name = "veth1";            // 默认监听接口名，可以根据实际情况修改，例如 "eth0", "ens33" 等
    unsigned char buffer[BUFFER_SIZE]; // 接收缓冲区
    struct sockaddr_ll sll;          // sockaddr_ll 结构，用于绑定接口
    struct ifreq ifr;                 // ifreq 结构，用于获取接口索引
    int if_index;                     // 接口索引
    int recv_len;                     // 接收到的数据包长度
    unsigned char dest_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // 示例目的 MAC 地址
    unsigned char src_mac[ETH_ALEN];      // 源 MAC 地址 (本地接口 MAC)
    unsigned char eth_type[2] = {0x08, 0x06}; // EtherType for ARP (示例，可以修改为其他 EtherType)
    unsigned char send_buf[BUFFER_SIZE];   // 发送缓冲区
    struct ether_header *eh;             // 以太网头部指针
                                         //

    // 1. 创建 AF_PACKET socket
    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // ETH_P_ALL 接收所有协议类型
    if (socket_fd == -1) {
        perror("socket() error");
        return -1;
    }
   // 2. 设置为非阻塞 I/O  ===  新增代码  ===
    int flags = fcntl(socket_fd, F_GETFL, 0); // 获取当前 flags
    if (flags == -1) {
        perror("fcntl(F_GETFL) error");
        close(socket_fd);
        return -1;
    }
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1) { // 设置 O_NONBLOCK flag
        perror("fcntl(F_SETFL, O_NONBLOCK) error");
        close(socket_fd);
        return -1;
    }
    printf("AF_PACKET socket created successfully.\n");

    // 2. 获取接口索引 (interface index)
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1); // 指定接口名
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl(SIOCGIFINDEX) error");
        close(socket_fd);
        return -1;
    }
    if_index = ifr.ifr_ifindex;
    printf("Interface index for %s: %d\n", if_name, if_index);

    // 3. 获取接口 MAC 地址 (源 MAC 地址)
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


    // 4. 绑定 socket 到指定接口
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_protocol = htons(ETH_P_ALL); // 接收所有协议类型
    if (bind(socket_fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        perror("bind() error");
        close(socket_fd);
        return -1;
    }
    printf("Socket bind to interface %s successfully.\n", if_name);

    /* create netbsd virtual interface */
    v_if = virt_if_create(if_name);
    virt_if_attach(v_if, src_mac);

    virt_if_register_callbacks(v_if, af_packet_output, af_packet_input);

    char *ip_str = "192.168.1.2";
    char *netmask_str = "255.255.255.0";
    char *gateway_str = "192.168.1.1";

    struct in_addr addr, gw;
    inet_pton(AF_INET, ip_str, &addr);
    inet_pton(AF_INET, gateway_str, &gw);
    unsigned netmask = 24;
    //inet_pton(AF_INET, netmask_str, &netmask);
    virt_if_add_addr(v_if, &addr, netmask, 1);
    //virt_if_add_gateway(v_if, &gw);
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
    write(socket_fd, (char *)data, len);
    return 0;
}

