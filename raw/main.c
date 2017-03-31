#include <stdio.h> //standard stuff (printf..)
#include <stdlib.h> //malloc
#include <string.h> //memset
#include <netinet/tcp.h> //declaration for tcp header
#include <netinet/ip.h> //declaration for ip header
#include <pthread.h> //threads
#include <errno.h> //strerr
#include <netdb.h> //NI_MAXHOST, NI_NUMERICHOST
#include <ifaddrs.h> //getifaddrs func
#include <time.h>

#include "handshake.h"

void hostname_toip(char *, struct in_addr *dst_ip);
int get_local_ip(char *);

int main(int argc, char *argv[])
{
    int sock_raw;
    struct in_addr dst_ip;

    //For every time rand func is called, be sure to generate different result
    srand(time(NULL));
    //I want source ports to be in range 50000-59999
    u_int16_t source_port = (rand() % 10000) + 50000;
    char source_ip[20] = "";

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sock_raw < 0)
    {
        perror("Socket error\n");
        return 1;
    }
    else
    {
        printf("Socket created.\n");
    }

    char *dst = argv[1];

    if(argc < 2)
    {
        fprintf(stderr, "Usage: %s <Hostname>\n", argv[0]);
        return 1;
    }

    //If hostname (argv[1]) is specified in numbers-and-dots notation, convert to network byte order
    if(inet_addr(dst) != INADDR_NONE)
    {
        //inet_addr converts dst from numbers-dots notaion to network byte order
        printf("Directly filling dst_ip.\n");
        dst_ip.s_addr = inet_addr(dst);
    }
    else
    {
        //Calls function hostname_toip which translates hostname to IP
        //printf("Calling addrinfo function, with a host: '%s'\n", dst);
        hostname_toip(dst, &dst_ip);
        //inet_ntoa needs whole in_addr struct
        printf("Your victim is: %s\n", inet_ntoa(dst_ip));
    }

    //printf("Your victim: %s\n", argv[1]);

//******************GET LOCAL IP**********************
    char *device, errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;

    device = pcap_lookupdev(errbuff);
    printf("Your default device is: %s\n", device);

    pcap_lookupnet(device, &net, &mask, errbuff);

    //struct in_addr tmp;
    //tmp.s_addr = net;

    //strcpy(source_ip, inet_ntoa(tmp));

    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    getifaddrs(&ifaddr);

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == NULL)
            continue;
        //min 8 field width between prints, with left alignment '-'
        //printf("%-8s\n", ifa->ifa_name);

        getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

        if(*(ifa->ifa_name) == *device && ifa->ifa_addr->sa_family==AF_INET)
        {
            //printf("IP: %s\n", host);
            strcpy(source_ip, host);
        }
    }
//*****************END OF GET LOCAL IP******************

    strcpy(source_ip, "192.168.0.140");

    printf("Local ip is: %s\n", source_ip);

    //IP header
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    char *packet_to_send;
    packet_to_send = (char *)malloc(60);

    //Zero out the packet memory area
    //memset(packet_to_send, 0, 4096);
    //Fill in the IP header
    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph.ip_id = htons(12345);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0; //Will be calculated afterwards
    iph.ip_src.s_addr = inet_addr(source_ip);
    iph.ip_dst.s_addr = dst_ip.s_addr;

    //Function that calculates checksum is implemented in trafgen
    iph.ip_sum = csum((unsigned short *) packet_to_send, iph.ip_len >> 1);

    memcpy(packet_to_send, &iph, sizeof(iph));

    //Fill in the TCP header
    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(0);
    tcph.th_ack = htonl(0);
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    tcph.th_flags = TH_SYN;
    tcph.th_win = htons(29200);
    tcph.th_sum = 0;
    tcph.th_urp = 0;
    tcph.th_sum = tcp_csum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, sizeof(tcph));

    memcpy((packet_to_send + sizeof(iph)), &tcph, sizeof(tcph));

    int one = 1;

    //IP_HDRINCL tells the kernel that headers are included
    if(setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        fprintf(stderr, "Error setting up setsockopt!\n");
        return 1;
    }

    printf("Starting sniffing.\n");
    int th1ret = 0;
    pthread_t thread1;

    //Creating thread with start_sniffing() function call, will start receiving packets and process them
    if(pthread_create(&thread1, NULL, (void *) start_sniffing, argv) < 0)
    {
        fprintf(stderr, "Failed to create a new thread.\n");
        return 1;
    }
    sleep(1);

    printf("Starting to send packets.\n");

    //dest - sockaddr_in
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    //Send the packet out
    if(sendto(sock_raw, packet_to_send, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        fprintf(stderr, "Error sending syn packet! Error message: %s\n", strerror(errno));
        exit(1);
    }
    int arg_count = 7;
    char *args[] = {"-c1", "-A", "-s", source_ip, "-I", "wlan0", "192.168.0.1"};
    arping_main(arg_count, args);

    //printf("Syn has been sent out.\n");
    pthread_join(thread1, NULL);
    //send_syn_ack(source_ip, &dst_ip, source_port);
    printf("Value returned from thread 1: %d\nProgram will now close.\n", th1ret);
    return 0;
}

void hostname_toip(char *dst, struct in_addr *dst_ip)
{
    struct addrinfo hints, *result;
    int addrinfores = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    //printf("Getting addrinfo of: %s\n", dst);

    //Translating hostname to IP
    addrinfores = getaddrinfo(dst, "80", &hints, &result);

    if(addrinfores != 0)
    {
        fprintf(stderr, "Getaddrinfo error: %s\n", strerror(errno));
        exit(0);
    }

    struct sockaddr_in *addr;
    //I can cast sockaddr to sockaddr_in which I need for writing to stdout
    addr = (struct sockaddr_in *) result->ai_addr;

    freeaddrinfo(result);
    //printf("You address: %s\n", inet_ntoa((struct in_addr) addr->sin_addr));

    //ai_addr is a struct in_addr what is the same type as dst_ip
    *dst_ip = addr->sin_addr;

    //I have dst_ip as a pointer here, that's why I need to pass *dst_ip
    //printf("Translated as: %s\n", inet_ntoa(*dst_ip));
}



