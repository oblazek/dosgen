#include "trafgen_wrapper.h"

void setup_optarg()
{
    optind = 1;
    opterr = 0;
    optopt = 0;
}

/* Funkction for chaning DNS name i.e. "www.google.com" to '0x03,"www",0x06,"google",0x03,"com"'
Originally took over from http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/, then edited to:
Funkce pro zmenu DNS jmena: "www.google.com" na '0x03,"www",0x06,"google",0x03,"com"'
Puvodne prevzata z vyse uvedeneho serveru, nasledne zmenena na: */
void ChangetoDnsNameFormat(unsigned char* dns,const unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
			//%02x prints at least 2 digits, prepend with 0 if there are less/format %02x vytiskne alespon 2 cislice, nalepi 0 dopredu, pokud ma jen 1 cislici 
            dns += sprintf(dns, "0x%02x,\"", i-lock); //i is holding 'dot' possition and 'lock' holds num of chars before 'dot' (www-3/google-6/com-3)/i udrzuje pozici tecky a lock udrzuje pocet znaku pred teckou

            for(; lock<i; lock++)
            {
				//append chars from *host to *dns until you get to index i (where the 'dot' was)/prilepi znaky z *hosta do *dns dokud nenarazi na index i (krome)
                *dns++=host[lock];
            }
            lock++;
            *dns++ = '\"';
            *dns++ = ',';
        }
    }
    *dns++='\0';
}

char * prepare_syn(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len)
{
    // Creating tmp file/Vytvoreni docasneho souboru
    char *cfg_file_name = "tmp.cfg";
	// Opening with append/Otevreni s parametrem append
    FILE *cfg = fopen(cfg_file_name, "a");
	// Testing if file was opened correctly/Testovani, zdali byl soubor spravne otevren
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }
    // Writing input parms to "trafgen_syn_cfg" string and saving to tmp file/Zapis vstupnich argumentu do retezce "trafgen_syn_cfg" a ulozeni do docasneho souboru
    fprintf(cfg, trafgen_syn_cfg, 40+len, src_ip, dst_ip, src_port, dst_port, len);
	// Closing tmp file/Zavreni docasneho souboru
    fclose(cfg);
}

char * prepare_rst(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }
    fprintf(cfg, trafgen_rst_cfg, 40+len, src_ip, dst_ip, src_port, dst_port, len);
    fclose(cfg);
}

char * prepare_udp(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }

    fprintf(cfg, trafgen_udp_cfg, 28+len, src_ip, dst_ip, src_port, dst_port, 8+len, len);
    fclose(cfg);

}

char * prepare_icmp(const char *src_ip, const char *dst_ip, const unsigned len)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }

    fprintf(cfg, trafgen_icmp_cfg, 28+len, src_ip, dst_ip, 42+len, len);
    fclose(cfg);


}

char * prepare_arp(const char *src_ip, const char *dst_ip, const unsigned len)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }
    fprintf(cfg, trafgen_arp_cfg, src_ip, dst_ip, len);
    fclose(cfg);


}

char * prepare_dns(const char *src_ip, const char *src_port, const char *dst_ip,  const unsigned len, const char *dns_name)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }

    char dns_buf[512];
    ChangetoDnsNameFormat(dns_buf, dns_name);

    fprintf(cfg, trafgen_dns_cfg, 45+strlen(dns_name)+len, src_ip, dst_ip, src_port, 25+strlen(dns_name)+len, dns_buf, len);
    fclose(cfg);

}

char * prepare_dhcp(const unsigned len)
{
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }
    fprintf(cfg, trafgen_dhcp_cfg, 272+len, 252+len, len);
    fclose(cfg);


}

void start_attack(char *dev, char *proc_num_str)
{
    int argc = 8; //10
    char *argv[] = {"trafgen", "--cpp", "--dev", dev, "--conf", "tmp.cfg", "--cpus", proc_num_str}; //"--rate", pps_str
    setup_optarg();
    trafgen_main(argc, argv);
}


