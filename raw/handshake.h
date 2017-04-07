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
#include <pthread.h>
#include <errno.h>

#include "../trafgen/csum.h"
#include "checksum.h"

#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_hl) & 0x0f)

//int send_syn(int sock_raw, char *source_ip, struct in_addr dst_ip, u_int16_t *source_port, char *argv[]);
void start_sniffing(char *argv[]);
void send_syn_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[]);
int packet_receive(u_char *argv[], const struct pcap_pkthdr *pkthdr, u_char *packet);
void slowloris(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[]);
void get_flood(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[]);

#endif
