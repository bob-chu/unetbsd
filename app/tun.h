#ifndef __TUN_H__
#define __TUN_H__

int open_af_packet();
void close_af_packet();
void print_packet(unsigned char *buf, int len);
int af_packet_input(char *data, long unsigned int len, void *arg);

#endif
