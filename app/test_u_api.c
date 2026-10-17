#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "u_api.h"
#include "init.h"

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;
    printf("=== UNETBSD u_* Extended API Verification Test ===\n");

    netbsd_init();
    printf("1. netbsd_init() completed successfully.\n");

    /* ------------------------------------------------------------- */
    /* Test 1: UDP Socket, sendmsg, recvmsg, sendmmsg, recvmmsg     */
    /* ------------------------------------------------------------- */
    printf("2. Testing UDP u_sendmsg and u_recvmsg on loopback...\n");
    int udp_srv = u_socket(AF_INET, SOCK_DGRAM, 0);
    assert(udp_srv >= 0);

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port = htons(18888);

    int ret = u_bind(udp_srv, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    assert(ret == 0);

    int udp_cli = u_socket(AF_INET, SOCK_DGRAM, 0);
    assert(udp_cli >= 0);

    /* Test single u_sendmsg */
    char send_buf[] = "HELLO_UNETBSD_QUIC";
    struct iovec siov = { .iov_base = send_buf, .iov_len = strlen(send_buf) };
    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_name = &srv_addr;
    smsg.msg_namelen = sizeof(srv_addr);
    smsg.msg_iov = &siov;
    smsg.msg_iovlen = 1;

    ssize_t nsent = u_sendmsg(udp_cli, &smsg, 0);
    assert(nsent == (ssize_t)strlen(send_buf));

    /* Tick the stack so the loopback packet moves through NetBSD queues */
    u_stack_tick();

    /* Test single u_recvmsg */
    char recv_buf[256];
    struct iovec riov = { .iov_base = recv_buf, .iov_len = sizeof(recv_buf) };
    struct sockaddr_in from_addr;
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_name = &from_addr;
    rmsg.msg_namelen = sizeof(from_addr);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;

    ssize_t nrecvd = u_recvmsg(udp_srv, &rmsg, 0);
    assert(nrecvd == (ssize_t)strlen(send_buf));
    assert(memcmp(recv_buf, send_buf, nrecvd) == 0);
    printf("   Single u_sendmsg and u_recvmsg PASSED!\n");

    /* ------------------------------------------------------------- */
    /* Test 2: UDP Batching: u_sendmmsg and u_recvmmsg              */
    /* ------------------------------------------------------------- */
    printf("3. Testing UDP u_sendmmsg and u_recvmmsg batching...\n");
    #define BATCH_SIZE 4
    char batch_send[BATCH_SIZE][32];
    struct iovec b_siov[BATCH_SIZE];
    struct mmsghdr b_smsg[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        snprintf(batch_send[i], sizeof(batch_send[i]), "PACKET_BURST_%d", i);
        b_siov[i].iov_base = batch_send[i];
        b_siov[i].iov_len = strlen(batch_send[i]);

        memset(&b_smsg[i], 0, sizeof(b_smsg[i]));
        b_smsg[i].msg_hdr.msg_name = &srv_addr;
        b_smsg[i].msg_hdr.msg_namelen = sizeof(srv_addr);
        b_smsg[i].msg_hdr.msg_iov = &b_siov[i];
        b_smsg[i].msg_hdr.msg_iovlen = 1;
    }

    int b_sent = u_sendmmsg(udp_cli, b_smsg, BATCH_SIZE, 0);
    assert(b_sent == BATCH_SIZE);

    /* Tick stack */
    u_stack_tick();

    char batch_recv[BATCH_SIZE][32];
    struct iovec b_riov[BATCH_SIZE];
    struct sockaddr_in b_from[BATCH_SIZE];
    struct mmsghdr b_rmsg[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        b_riov[i].iov_base = batch_recv[i];
        b_riov[i].iov_len = sizeof(batch_recv[i]);

        memset(&b_rmsg[i], 0, sizeof(b_rmsg[i]));
        b_rmsg[i].msg_hdr.msg_name = &b_from[i];
        b_rmsg[i].msg_hdr.msg_namelen = sizeof(b_from[i]);
        b_rmsg[i].msg_hdr.msg_iov = &b_riov[i];
        b_rmsg[i].msg_hdr.msg_iovlen = 1;
    }

    int b_recvd = u_recvmmsg(udp_srv, b_rmsg, BATCH_SIZE, 0, NULL);
    assert(b_recvd == BATCH_SIZE);
    for (int i = 0; i < BATCH_SIZE; i++) {
        assert(memcmp(batch_recv[i], batch_send[i], b_rmsg[i].msg_len) == 0);
    }
    printf("   UDP u_sendmmsg and u_recvmmsg (batch size 4) PASSED!\n");

    u_close(udp_cli);
    u_close(udp_srv);

    /* ------------------------------------------------------------- */
    /* Test 3: TCP u_accept4 with SOCK_NONBLOCK                      */
    /* ------------------------------------------------------------- */
    printf("4. Testing TCP u_accept4 with SOCK_NONBLOCK...\n");
    int tcp_srv = u_socket(AF_INET, SOCK_STREAM, 0);
    assert(tcp_srv >= 0);

    struct sockaddr_in tcp_srv_addr;
    memset(&tcp_srv_addr, 0, sizeof(tcp_srv_addr));
    tcp_srv_addr.sin_family = AF_INET;
    tcp_srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    tcp_srv_addr.sin_port = htons(19999);

    int opt = 1;
    u_setsockopt(tcp_srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    ret = u_bind(tcp_srv, (struct sockaddr *)&tcp_srv_addr, sizeof(tcp_srv_addr));
    assert(ret == 0);

    ret = u_listen(tcp_srv, 10);
    assert(ret == 0);

    /* Before any connection, u_accept4 should return -1 with EAGAIN or EWOULDBLOCK */
    u_set_nonblocking(tcp_srv, 1);
    struct sockaddr_in cli_peer;
    socklen_t cli_peer_len = sizeof(cli_peer);
    int empty_accept = u_accept4(tcp_srv, (struct sockaddr *)&cli_peer, &cli_peer_len, 0x800 /* SOCK_NONBLOCK */);
    assert(empty_accept < 0);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);

    /* Connect client */
    int tcp_cli = u_socket(AF_INET, SOCK_STREAM, 0);
    assert(tcp_cli >= 0);
    u_set_nonblocking(tcp_cli, 1);

    ret = u_connect(tcp_cli, (struct sockaddr *)&tcp_srv_addr, sizeof(tcp_srv_addr));
    /* Non-blocking connect returns EINPROGRESS or 0 */
    assert(ret == 0 || errno == EINPROGRESS);

    /* Tick stack for SYN-ACK handshake */
    for (int t = 0; t < 10; t++) {
        user_hardclock();
        u_stack_tick();
    }

    /* Accept connection with SOCK_NONBLOCK */
    int accepted_fd = u_accept4(tcp_srv, (struct sockaddr *)&cli_peer, &cli_peer_len, 0x800 /* SOCK_NONBLOCK */);
    assert(accepted_fd >= 0);
    assert(u_is_nonblocking(accepted_fd) == 1);
    printf("   TCP u_accept4(SOCK_NONBLOCK) returned fd %d (non-blocking confirmed) PASSED!\n", accepted_fd);

    u_close(tcp_cli);
    u_close(accepted_fd);
    u_close(tcp_srv);

    printf("\n=== ALL UNETBSD EXTENDED API TESTS PASSED SUCCESSFULLY! ===\n");
    return 0;
}
