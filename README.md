Trafgen part cloned from https://github.com/netsniff-ng/netsniff-ng.git and edited to be used as a standalone tool for DoS attacks. <br /> 

Tool is using raw sockets and libpcap library for receiving and processing packets, got from server. 

For purposes of arp injection, iputils-arping tool is used as a statically linked library.

Implemented are following attacks:	- SYN flood  
									- RST flood  
									- UDP flood  
									- ICMP flood  
									- ARP flood  
									- DNS flood	 
									- DHCP starvation  
                                    - Slowloris
Attack now being implemented:       - HTTP GET




