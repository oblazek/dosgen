#include <stdio.h> //standard stuff (printf..)
#include <stdlib.h> //malloc
#include <string.h> //memset
#include <netinet/tcp.h> //declaration for tcp header
#include <netinet/ip.h> //declaration for ip header
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h> //strerr
//#include <sys/types.h>
#include <netdb.h>
#include "../dosgen/dosgen/trafgen/csum.h"

void process_packet(unsigned char*, int, struct in_addr *dst_ip);
void print_ip_header(unsigned char*, int);
void print_tcp_header(unsigned char*, int);
void hostname_toip(char *, struct in_addr *dst_ip);
int get_local_ip(char *);
void receive_ack(struct in_addr *dst_ip);

int sock_raw;
FILE *logfile;
int tcp=0, others=0, total=0, i, j;
struct sockaddr_in source, dest;


//For checksum
struct pseudo_header {
    unsigned int src_address;
    unsigned int dst_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
};



int main(int argc, char *argv[])
{
    struct in_addr dst_ip;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if(sock_raw < 0)
    {
        printf("Socket error\n");
        return 1;
    }
    else
    {
        printf("Socket created.\n");
    }

    char packet_to_send[4096];


    //IP header
    struct iphdr *iph = (struct iphdr *) packet_to_send;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (packet_to_send + sizeof(struct ip));

    struct sockaddr_in dest;
    struct pseudo_header pshdr;

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
        printf("Calling addrinfo function, with a host: '%s'\n", dst);
        hostname_toip(dst, &dst_ip);
        //inet_ntoa need whole in_addr struct
        printf("Value returned: %s\n", inet_ntoa(dst_ip));
    }

    int source_port = 55555;
    char source_ip[20] = "10.0.0.40";
    //get_local_ip(source_ip);

    printf("Local ip is: %s\n", source_ip);

    //Zero out the packet memory area
    memset(packet_to_send, 0, 4096);

    //Fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->id = htons(12345);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Will be calculated afterwards
    iph->saddr = inet_addr(source_ip);
    iph->daddr = dst_ip.s_addr;

    //Function that calculates checksum is implemented in trafgen
    iph->check = csum((unsigned short *) packet_to_send, iph->tot_len >> 1);

    memcpy(&packet_to_send, &iph, sizeof(iph));

    //Fill in the TCP header
    tcph->source = htons(source_port);
    tcph->dest = htons(80);
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->urg = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 1;
    tcph->fin = 0;
    tcph->window = htons(14600);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    memcpy(&packet_to_send, &tcph, sizeof(tcph));

    int one = 1;

    //IP_HDRINCL tells the kernel that headers are included
    if(setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        fprintf(stderr, "Error setting up setsockopt!\n");
        return 1;
    }

    printf("Starting sniffing.\n");
    char *thread1Message = "Thread 1";
    int th1ret = 0;
    pthread_t thread1;

    //Creating thread with receive_ack() function call, will start receiving packets and process them
    //if(pthread_create(&thread1, NULL, receive_ack(), &dst_ip) < 0)
    //{
    //    fprintf(stderr, "Failed to create a new thread.\n");
    //    return 1;
    //}

    printf("Starting to send syn packets.\n");

    int port = 80;
    //dest - sockaddr_in
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dst_ip.s_addr;
    dest.sin_port = htons(port);

    //tcph->dest = htons(port);
    //tcph->check = 0;

    pshdr.src_address = inet_addr(source_ip);
    pshdr.dst_address = dst_ip.s_addr;
    pshdr.placeholder = 0;
    pshdr.protocol = IPPROTO_TCP;
    pshdr.tcp_length = htons(sizeof(struct tcphdr));

    //Copies mem area from tcph to pshdr.tcp
    //memcpy(&pshdr.tcp, tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)&tcph, sizeof(struct tcphdr));

    //Send the packet out
    if(sendto(sock_raw, packet_to_send, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(dest)) < 0)
    {
        fprintf(stderr, "Error sending syn packet! Error message: %s\n", strerror(errno));
        exit(0);
    }

    pthread_join(thread1, NULL);
    printf("%d\n", th1ret);

    return 0;
}

void hostname_toip(char *dst, struct in_addr *dst_ip)
{
    struct addrinfo hints, *result;
    int addrinfores = 0;

   // if ((h = malloc(sizeof (struct sockaddr_in))) == NULL)
   //     return NULL;

    char ipv4[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    printf("Getting addrinfo of: %s\n", dst);

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
    printf("You address: %s\n", inet_ntoa((struct in_addr) addr->sin_addr));

    //ai_addr is a struct in_addr what is the same type as dst_ip
    *dst_ip = addr->sin_addr;

    //I have dst_ip as a pointer here, that's why I need to pass *dst_ip
    printf("Translated as: %s\n", inet_ntoa(*dst_ip));
}

//int get_local_ip(char *source_ip)
//{
//
//}

void receive_ack(struct in_addr *dst_ip)
{
    start_sniffing(&dst_ip);
}

int start_sniffing(struct in_addr *dst_ip)
{
    int socket_raw;
    int data_size;

    struct sockaddr saddr;
    unsigned int saddr_size;

    //Access to the buffer using dynamic mem alloc
    unsigned char *buffer = (unsigned char *) malloc(65536);

    printf("Starting up the sniffer!\n");
    fflush(stdout);

    //Creating raw socket used for sniffing
    socket_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock_raw < 0)
    {
        fprintf(stderr, "Failed to create a socket. Error message: %s", strerror(errno));
        fflush(stdout);
        return 1;
    }
    printf("Receiving packets");
    saddr_size = sizeof(saddr);

    while(1)
    {
        //Receive a packet
        data_size = recvfrom(socket_raw, buffer, 65535, 0, &saddr, &saddr_size);

        if(data_size < 0)
        {
            printf("Recvfrom error, failed to get packets! Error message: %s\n", strerror(errno));
            fflush(stdout);
            return 1;
        }

        //Now process the packet
        process_packet(buffer, data_size, dst_ip);
    }

    close(sock_raw);
    printf("Finished sniffing");
    fflush(stdout);
    return 0;
}

void process_packet(unsigned char *buffer, int data_size, struct in_addr *dst_ip)
{
    //Get the IP header
    struct iphdr *iph = (struct iphdr *)buffer;
    struct sockaddr_in source, destination;
    unsigned short iphdrlength;

    //If upper level protocol is TCP then...
    if(iph->protocol == 6)
    {
        iphdrlength = iph->ihl*4;

        struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlength);

        //Fill memory used by "source" with zeros
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;

        memset(&destination, 0, sizeof(destination));
        destination.sin_addr.s_addr = iph->daddr;

        if(tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == dst_ip->s_addr)
        {
            printf("You just received an ack message!\n");
            fflush(stdout);
        }

    }

}


