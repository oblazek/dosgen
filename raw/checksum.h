#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdlib.h> //exit, malloc, u_int8 types
#include <netinet/in.h> //IPPROTO_TCP, u_int16 types
#include <string.h> //memset, memcpy
#include <netinet/tcp.h> //declaration for tcp header
#include <netinet/ip.h> //declaration for ip header

//For checksum
struct pseudo_tcp {
    unsigned int src_address;
    unsigned int dst_address;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

u_int16_t tcp_chksum(struct ip, struct tcphdr, uint8_t *, int);
u_int16_t chksum(u_int16_t *, int);
unsigned short in_cksum(unsigned short *addr, int len);
unsigned short tcp_csum(int src, int dst, unsigned short *addr, int len);

#endif
