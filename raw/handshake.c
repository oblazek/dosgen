#include "handshake.h"

unsigned short in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

unsigned short tcp_csum(int src, int dst, unsigned short *addr, int len)
{
    struct pseudo_tcp buf;
    u_short ans;

    memset(&buf, 0, sizeof(buf));

    buf.src_address = src;
    buf.dst_address = dst;
    buf.reserved = 0;
    buf.protocol = IPPROTO_TCP;
    buf.tcp_length = htons(len);

    memcpy(&(buf.tcp), addr, len);

    ans = in_cksum((unsigned short *)&buf, 12 + len);

    return ans;
}

int start_sniffing(char *argv[])
{
    pcap_t *descr;
    char filter[30];
    sprintf(filter, "host %s", argv[1]);
    char *dev = "eth0";
    char error_buffer[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net;
    bpf_u_int32 mask;

    struct bpf_program filterf;

    if((descr = pcap_open_live(dev, BUFSIZ, 1, -1, error_buffer)) == NULL)
    {
        perror("Could not open a pcap device.\n");
        return 1;
    }

    //looking up net/mask for given dev
    pcap_lookupnet(dev, &net, &mask, error_buffer);

    //compiling filter expression
    pcap_compile(descr, &filterf, filter, 0, net);


    if(pcap_setfilter(descr, &filterf) == -1)
    {
        perror("Error setting up pcap filter.\n");
        return 1;
    }

    //freeing a bpf program
    pcap_freecode(&filterf);

    //getting link-layer header type = 1 means Ethernet according to IEEE 802.3
    int hdr_type = pcap_datalink(descr);
    //int length = 0;

    if(hdr_type == 1)
        //sizeof ethernet header is 14
        //length = 14;
        //int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
        if(pcap_loop(descr, -1, (void *) packet_receive, (u_char *) argv) < 0)
        {
            perror("Cannot get raw packet.\n");
            return 1;
        }

    return 0;
}

void packet_receive(u_char *argv[], const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("---------------------------\n");
    printf("GOT PACKET!\n");
    printf("---------------------------\n");

    struct ip *ip;
    struct tcphdr *tcp;
    //u_char *ptr;

    ip = (struct ip *)(packet + sizeof(struct ether_header));
    //printf("Size of ether_header is: %d\n", sizeof(struct ether_header));
    tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + (IP_HL(ip)*4));


    //printf("%d\n", l1_len);
    printf("Packet came along with src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("Packet came along with dst IP: %s\n", inet_ntoa(ip->ip_dst));

    printf("Packet came with seq: %u\n", ntohl(tcp->th_seq));
    printf("Packet came with ack: %u\n", ntohl(tcp->th_ack));
    //& is a binary AND
    if(tcp->th_flags & TH_SYN)
        printf("Packet has a flags set as SYN!\n");
    if(tcp->th_flags & TH_ACK)
        printf("Packet has a flags set as ACK!\n");
    if(tcp->th_flags & TH_RST)
        printf("Packet has a flags set as RST!\n");
    if(tcp->th_flags & TH_FIN)
        printf("Packet has a flags set as FIN!\n");
    if(tcp->th_flags & TH_PUSH)
        printf("Packet has a flags set as PUSH!\n");
    //seq_n = ntohl(tcp->th_seq);
    if((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK))
    {
        u_int32_t seq_n = ntohl(tcp->th_seq);
        //printf("Sequence num is: %u\n", seq_n);

        send_syn_ack(((u_int32_t *)&ip->ip_dst.s_addr), (u_int32_t *)&ip->ip_src.s_addr, (u_short)ntohs(tcp->th_dport), seq_n, argv);

    }
}

void send_syn_ack(u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_char *argv[])
{
    struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    int sock_raw;

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    char *pkt_syn_ack;
    pkt_syn_ack = (char *) malloc(60);

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

    printf("Source port in ACK message is: %u\n", source_port);
    memcpy(pkt_syn_ack, &iph, sizeof(iph));

    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(1);
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

    send_data(&sock_raw, source_ip, dst_ip, source_port, seq, ntohl(tcph.th_ack), argv);

    //printf("Syn_Ack packet has been sent out!\n");

}

void send_data(int *sock_raw, u_int32_t *source_ip, u_int32_t *dst_ip, u_short source_port, u_int32_t seq, u_int32_t ack, u_char *argv[])
{
    /*struct ip iph;
    struct tcphdr tcph;
    struct sockaddr_in dest;

    printf("Victim: %s\n", argv[1]);
    char *pkt_data;
    pkt_data = (char *) malloc(60);

    uint8_t *packet;

    sprintf(pkt_data, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", argv[1]);

    int pkt_data_len = strlen(pkt_data);

    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + pkt_data_len;
    iph.ip_id = htons(12348);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0;
    iph.ip_src.s_addr = source_ip;
    iph.ip_dst.s_addr = dst_ip;
    iph.ip_sum = csum((unsigned short *) pkt_data, iph.ip_len >> 1);

    memcpy(packet, &iph, sizeof(iph));

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

    memcpy(packet + sizeof(iph), &tcph, sizeof(tcph));
    memcpy(packet + sizeof(iph) + sizeof(tcph), pkt_data, pkt_data_len * sizeof(uint8_t));

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    //int one = 1;

    //IP_HDRINCL tells the kernel that headers are included
    //if(setsockopt(*sock_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    //{
    //    fprintf(stderr, "Error setting up setsockopt!\n");
    //    exit(1);
    //}

    if(sendto(*sock_raw, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + pkt_data_len, 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Failed to send syn_ack packet!\n");
        exit(1);
    }*/
}
