<img src=https://img.shields.io/travis/rust-lang/rust.svg></img>
<img src=https://img.shields.io/badge/gcc-5.4.0-brightgreen.svg></img>
<img src=https://img.shields.io/badge/qmake-2.01a-brightgreen.svg></img>

Tool currently made of two separate parts. Trafgen part cloned from https://github.com/netsniff-ng/netsniff-ng.git and edited to be used as a standalone tool for DoS attacks. 

Raw project is the second part which uses pthreads, raw sockets and libpcap library.<br /> 

For purposes of arp injection, iputils-arping tool is used.

Implemented are following attacks:	- SYN flood  
									- RST flood  
									- UDP flood  
									- ICMP flood  
									- ARP flood  
									- DNS flood	 
                                    - DHCP starvation  
                                    - Slowloris 

Attack now being implemented:       - HTTP GET




