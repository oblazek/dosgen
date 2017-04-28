<img src=https://img.shields.io/travis/rust-lang/rust.svg></img>
<img src=https://img.shields.io/badge/gcc-5.4.0-brightgreen.svg></img>
<img src=https://img.shields.io/badge/qmake-2.01a-brightgreen.svg></img>

Tool currently made of two separate modules. Trafgen part cloned from https://github.com/netsniff-ng/netsniff-ng.git and edited to be used as a standalone tool for DoS attacks. 

Tcpgen project is the second part which uses pthreads, raw sockets, libpcap library and is also included as a static library.<br /> 

For purposes of arp injection, iputils-arping tool is used.

Implemented are following attacks:	- SYN flood  
									- RST flood  
									- UDP flood  
									- ICMP flood  
									- ARP flood  
									- DNS flood	 
                                    - DHCP starvation  
                                    - Slow loris 
                                    - HTTP GET  
                                    - Sockstress  
                                    - Slow read  




