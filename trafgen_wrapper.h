#ifndef TRAFGEN_WRAPPER_H
#define TRAFGEN_WRAPPER_H

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "trafgenlib.h"
#include "trafgen_configs.h"


char * prepare_syn(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len);
char * prepare_rst(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len);
char * prepare_udp(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len);
char * prepare_icmp(const char *src_ip, const char *dst_ip, const unsigned len);
char * prepare_arp(const char *src_ip, const char *dst_ip, const unsigned len);
char * prepare_dns(const char *src_ip, const char *src_port, const char *dst_ip, const unsigned len, const char *dns_name);
char * prepare_dhcp(const unsigned len);
char * prepare_http_get(const char *src_ip, const char *dst_ip, const char *host_name, const unsigned len);
void start_attack(char *dev, char *proc_num_str); // char *pps_str


#endif
