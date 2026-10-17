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
    assert(cli_peer.sin_family == AF_INET);
    assert(cli_peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    printf("   TCP u_accept4(SOCK_NONBLOCK) returned fd %d (non-blocking confirmed) PASSED!\n", accepted_fd);

    /* ------------------------------------------------------------- */
    /* Test 4: TCP Bidirectional Data Transfer (u_write & u_read)   */
    /* ------------------------------------------------------------- */
    printf("5. Testing TCP bidirectional data transfer (u_write / u_read)...\n");
    char tcp_msg[] = "UNETBSD_TCP_DATA_PAYLOAD";
    ssize_t w_sent = u_write(tcp_cli, tcp_msg, strlen(tcp_msg));
    assert(w_sent == (ssize_t)strlen(tcp_msg));

    for (int t = 0; t < 5; t++) {
        user_hardclock();
        u_stack_tick();
    }

    char tcp_rbuf[128] = {0};
    ssize_t r_recvd = u_read(accepted_fd, tcp_rbuf, sizeof(tcp_rbuf) - 1);
    assert(r_recvd == (ssize_t)strlen(tcp_msg));
    assert(memcmp(tcp_rbuf, tcp_msg, r_recvd) == 0);

    /* Echo back from server to client */
    char tcp_echo[] = "UNETBSD_TCP_ECHO_RESPONSE";
    ssize_t e_sent = u_write(accepted_fd, tcp_echo, strlen(tcp_echo));
    assert(e_sent == (ssize_t)strlen(tcp_echo));

    for (int t = 0; t < 5; t++) {
        user_hardclock();
        u_stack_tick();
    }

    char cli_rbuf[128] = {0};
    ssize_t c_recvd = u_read(tcp_cli, cli_rbuf, sizeof(cli_rbuf) - 1);
    assert(c_recvd == (ssize_t)strlen(tcp_echo));
    assert(memcmp(cli_rbuf, tcp_echo, c_recvd) == 0);
    printf("   TCP bidirectional u_write and u_read PASSED!\n");

    /* ------------------------------------------------------------- */
    /* Test 5: TCP Multi-Kilobyte Stream & Window Drain             */
    /* ------------------------------------------------------------- */
    printf("6. Testing TCP 16KB stream data transfer...\n");
    #define STREAM_BYTES 16384
    char *stream_data = malloc(STREAM_BYTES);
    assert(stream_data != NULL);
    for (int i = 0; i < STREAM_BYTES; i++) {
        stream_data[i] = (char)(i & 0xFF);
    }

    ssize_t stream_sent = u_write(tcp_cli, stream_data, STREAM_BYTES);
    assert(stream_sent > 0);

    size_t total_stream_recvd = 0;
    char *stream_recv_buf = malloc(STREAM_BYTES);
    assert(stream_recv_buf != NULL);

    for (int round = 0; round < 100 && total_stream_recvd < STREAM_BYTES; round++) {
        user_hardclock();
        u_stack_tick();
        ssize_t n = u_read(accepted_fd, stream_recv_buf + total_stream_recvd, STREAM_BYTES - total_stream_recvd);
        if (n > 0) {
            total_stream_recvd += n;
        }
        if (stream_sent < STREAM_BYTES) {
            ssize_t rem = u_write(tcp_cli, stream_data + stream_sent, STREAM_BYTES - stream_sent);
            if (rem > 0) stream_sent += rem;
        }
    }
    assert(total_stream_recvd == STREAM_BYTES);
    assert(memcmp(stream_data, stream_recv_buf, STREAM_BYTES) == 0);
    free(stream_data);
    free(stream_recv_buf);
    printf("   TCP 16KB stream transfer verified PASSED!\n");

    /* ------------------------------------------------------------- */
    /* Test 6: TCP Half-Close (u_shutdown SHUT_WR) & EOF Detection  */
    /* ------------------------------------------------------------- */
    printf("7. Testing TCP u_shutdown(SHUT_WR) and EOF detection...\n");
    ret = u_shutdown(tcp_cli, SHUT_WR);
    assert(ret == 0);

    for (int t = 0; t < 10; t++) {
        user_hardclock();
        u_stack_tick();
    }

    char eof_buf[16];
    ssize_t eof_res = u_read(accepted_fd, eof_buf, sizeof(eof_buf));
    /* Reading from half-closed socket with no more data returns 0 (EOF) */
    assert(eof_res == 0);
    printf("   TCP u_shutdown(SHUT_WR) and EOF detection PASSED!\n");

    u_close(tcp_cli);
    u_close(accepted_fd);
    u_close(tcp_srv);

    printf("\n=== ALL UNETBSD EXTENDED API TESTS PASSED SUCCESSFULLY! ===\n");
    return 0;
}
