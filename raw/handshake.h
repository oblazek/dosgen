#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <netinet/in.h>
#include <pcap.h>
#include <netinet/if_ether.h> //declaration for ether header
#include <netinet/tcp.h> //declaration for tcp header
#include <netinet/ip.h> //declaration for ip header
#include <stdlib.h> //exit, malloc
#include <arpa/inet.h> //inet_ntoa...
#include <string.h> //memset
#include <unistd.h> //sleep

#include "../trafgen/csum.h"

#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_hl) & 0x0f)

//For checksum
struct pseudo_tcp {
    unsigned int src_address;
    unsigned int dst_address;
    unsigned char reserved;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};

unsigned short in_cksum(unsigned short *addr, int len);
unsigned short tcp_csum(int src, int dst, unsigned short *addr, int len);
int start_sniffing(char *argv[]);
void send_syn_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_char *argv[]);
void packet_receive(u_char *argv[], const struct pcap_pkthdr *pkthdr, const u_char *packet);
void send_data(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[]);

#endif
