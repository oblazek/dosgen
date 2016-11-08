#include "trafgen_wrapper.h"

void setup_optarg()
{
    optind = 1;
    opterr = 0;
    optopt = 0;
}

/* Funkcia na zmenu formátu DNS mena (www.google.com -> 0x03,"www",0x06,"google",0x03,"com")
Pôvodne prevzatá z http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/ , následne upravená */
void ChangetoDnsNameFormat(unsigned char* dns,const unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {

            dns += sprintf(dns, "0x%02x,\"", i-lock);

            for(; lock<i; lock++)
            {
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
    // Vytvorenie dočasného súboru
    char *cfg_file_name = "tmp.cfg";
    FILE *cfg = fopen(cfg_file_name, "a");
    if (cfg == NULL)
    {
        return "Failed to open config file";
    }
    // Zápis vstupných argumentov do reťazca "trafgen_syn_cfg" a následné uloženie do dočasného súboru
    fprintf(cfg, trafgen_syn_cfg, 40+len, src_ip, dst_ip, src_port, dst_port, len);
    fclose(cfg);
}

char * prepare_rst(const char *src_ip, const char *src_port, const char *dst_ip, const char *dst_port, const unsigned len)
{
    // Vytvorenie dočasného súboru
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


