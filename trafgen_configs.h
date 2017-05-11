#ifndef TRAFGEN_CONFIGS_H
#define TRAFGEN_CONFIGS_H


char *tcp_syn_cfg =     "{"
                        "fill(0xff, 6), " 	// Destination MAC address/Cilova MAC adresa                                                                    /
			"0xec, 0xf4, 0xbb, 0x0f, 0xb0, 0xb1, "	// Source MAC address/Zdrojova MAC adresa              						MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4	 						/
			"0b01000101, 0, "		// IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS 			x
			"const16(%u), "			// Overall length (IP + TCP)/Celkova delka (IP + TCP) 							x
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator								x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat					        x
 			"64, "				// TTL (Time to Live)											IP header
			"0x06, "			// Used protocol, 0x06 in HEX means TCP protocol/Protokol, hodnota 0x06 v hexa soustave znaci TCP	x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)						x
			"%s, "				// Source IP/Zdrojova IP adresa										x
			"%s, " 				// Destination IP/Cilova IP adresa									x
			"%s, "				// Source port/Zdrojovy port 										!
			"%s, " 				// Destination/Cilovy port 										!
			"drnd(4), "			// Sequence number/Sekvencni cislo 									!
			"const32(0), "			// Acknowledgment number/ACK cislo 									!
			"const16((0x5 << 12) | (1 << 1)), "// Header length(Data offset)/Delka TCP zahlavi (v 32b slovech) + priznak SYN		TCP header
			"const16(512), "		// Window Size/Velikost okna TCP									!
			"csumtcp(14, 34), "		// Checksum/Vypocet kontrolniho souctu IP + TCP (od, do)						!
			"const16(0), "			// Urgent pointer											!
			"fill(0x00, %u), "		// Filling/Vypln 											!
			"}";
                        
char *trafgen_syn_cfg = "{"
			"fill(0xff, 6), " 	// Destination MAC address/Cilova MAC adresa                                                                    /
			"0x9c, 0x4e, 0x36, drnd(3), "	// Source MAC address/Zdrojova MAC adresa		 						MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4	 						/
			"0b01000101, 0, "		// IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS 			x
			"const16(%u), "			// Overall length (IP + TCP)/Celkova delka (IP + TCP) 							x
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator								x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat						x
 			"64, "				// TTL (Time to Live)											IP header
			"0x06, "			// Used protocol, 0x06 in HEX means TCP protocol/Protokol, hodnota 0x06 v hexa soustave znaci TCP	x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)						x
			"%s, "				// Source IP/Zdrojova IP adresa										x
			"%s, " 				// Destination IP/Cilova IP adresa									x
			"%s, "				// Source port/Zdrojovy port 										!
			"%s, " 				// Destination/Cilovy port 										!
			"drnd(4), "			// Sequence number/Sekvencni cislo 									!
			"const32(0), "			// Acknowledgment number/ACK cislo 									!
			"const16((0x5 << 12) | (1 << 1)), "// Header length(Data offset)/Delka TCP zahlavi (v 32b slovech) + priznak SYN		TCP header
			"const16(512), "		// Window Size/Velikost okna TCP									!
			"csumtcp(14, 34), "		// Checksum/Vypocet kontrolniho souctu IP + TCP (od, do)						!
			"const16(0), "			// Urgent pointer											!
			"fill(0x00, %u), "		// Filling/Vypln 											!
			"}";

char *trafgen_rst_cfg = "{"
			"fill(0xff, 6), "	// Destination MAC address/Cilova MAC adresa                                                                    /									
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa								MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4							/
			"0b01000101, 0, "		//IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS             	        x	
			"const16(%u), "			//Overall length (IP + TCP)/Celkova delka (IP + TCP)                                           	        x 
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator                                                           	x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat                                		x
 			"64, "				// TTL (Time to Live)											IP header
			"0x06, "			// Used protocol, 0x06 in HEX means TCP protocol/Protokol, hodnota 0x06 v hexa soustave znaci TCP       x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)                                               x
			"%s, "				// Source IP/Zdrojova IP adresa                                                                         x
			"%s, " 				// Destination IP/Cilova IP adresa                                                                      x
			"%s, "				// Source port/Zdrojovy port                                                                            ! 
			"%s, " 				// Destination/Cilovy port                                                                              ! 
			"drnd(4), "			// Sequence number/Sekvencni cislo                                                                      ! 
			"const32(0), "			// Acknowledgment number/ACK cislo                                                                      ! 
			"const16((0x5 << 12) | (1 << 2)), "// Data offset/Delka TCP zahlavia (v 32b slovech) + priznak RST					TCP header
			"const16(512), "		// Window Size/Velikost okna TCP                                                                        !
			"csumtcp(14, 34), "		// Checksum/Vypocet kontrolniho souctu IP + TCP (od, do)                                                !
			"const16(0), "			// Urgent pointer											!
			"fill(0x00, %u), "		// Filling/Vypln											! 
			"}";
			
char *trafgen_udp_cfg = "{"
			"fill(0xff, 6), " 		 // Destination MAC address/Cilova MAC adresa                                                           /   
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa								MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4							/
			"0b01000101, 0, "		//IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS             	        x
                        "const16(%u), "			//Overall length (IP + UDP)/Celkova delka (IP + UDP) 							x						
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator                                                                x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat                                 		x
 			"64, "				// TTL (Time to Live)											IP header
			"0x11, "			// Used protocol, 0x11 means UDP (17 in dec)/Pole protokol, cislo 0x11h znaci UDP (v dec 17)		x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)                                               x
			"%s, "			      	// Source IP/Zdrojova IP adresa                                                                         x
			"%s, " 				// Destination IP/Cilova IP adresa                                                                      x
			"%s, "				// Source port/Zdrojovy port UDP                                                                        !
			"%s, " 				// Destination/Cilovy port UDP                                                                          !
			"const16(%u), "			// UDP Length/Delka UDP 										UDP header
			"const16(0), "			// Checksum/Vypocet kontrolniho souctu (pro UDP je povolena 0)						!
			"fill(0x00, %u), "		// Filling/Vypln 											!
			"}";
			
char *trafgen_icmp_cfg ="{"
			"fill(0xff, 6), " 		 // Destination MAC address/Cilova MAC adresa                                                           /
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa								MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4							/
			"0b01000101, 0, "		//IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS                      x
			"const16(%u), "			//Overall length (IP + ICMP)/Celkova delka (IP + ICMP) 							x
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator                                                                x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat                                 		x
			"64, "				// TTL (Time to Live)											IP header
			"0x01, "			// Used protocol, 0x01 is for ICMP/Protokol - 0x01 znaci ICMP						x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)                                               x
			"%s, "				// Source IP/Zdrojova IP adresa                                                                         x
			"%s, " 				// Destination IP/Cilova IP adresa                                                                      x
			"0x08, "			// ICMP type - 0x08 for echo request/Typ ICMP zpravy							!
			"0x00, "			// ICMP subtype (code) 0x00 for echo request/ICMP subtyp (kod) 0x00 pro echo request			!
			"csumip(14, %u) "		// Checksum/Vypocet kontrolniho souctu IP + ICMP 							ICMP header
			"drnd(4), "			// Sequence number/Sekvencni cislo                                                                      !
			"fill(0x00, %u), "		// Filling/Vypln 																				
			"}";

char *trafgen_arp_cfg = "{"
			"fill(0xff, 6), " 		 // Destination MAC address/Cilova MAC adresa                                                   /
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa												MAC header
			"const16(0x0806), "		// EtherType pre ARP																			/
			"0x00,0x01, "			// HRD - Hardware Type -> 0x01 for Ethernet 2B in size/HW Typ - 0x01 pro ethernet 2B velikost	x
			"0x08,0x00, "			// PRO - Protocol type - IPv4 should be 0x0800/Typ protokolu 0x0800 pro IPv4					x
			"6, "				// HLN - Hardware address length - for IEEE 802 MAC addresses - 6 in dec/Delka HW adresy "6" v dec  x
			"4, "				// PLN - Protocol address length - for IPv4 value is 4/Delka adresy protokolu pro IPv4 = 4			x
			"0x00, 0x01, "			// OP - 2B Opcode - type of ARP message/specifikuje typ ARP zpravy - 1 for ARP request			ARP header
			"0x9c, 0x4e, 0x36, drnd(3), "	// SHA - Source HW(MAC) address/MAC adresa odesilatele - bude v odpovedi				x
			"%s, "				// SPA - Source protocol address/IP adresa odesilatele												x
			"fill(0x00, 6), " 		// THA - Destination(Target) HW address/MAC adresa cile											x
			"%s, "				// TPA - Destination(Target) protocol address/IP adresa cile										x 
			"fill(0x00, %u), "		// Filling/Vypln	
			"}";	

char *trafgen_dns_cfg = "{"
			"fill(0xff, 6), " 		 // Destination MAC address/Cilova MAC adresa                                                  	/
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa												MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4											/
			"0b01000101, 0, "		//IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS             	x
			"const16(%u), "			// Overall length/Celkova delka, 60																x
			"drnd(2), "			// IPv4 identificator/IPv4 identifikator                                                            x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat                                 		x
			"64, "				// TTL (Time to Live)																				IP header
			"0x11, "			// Used protocol, 0x11 means UDP (17 in dec)/Pole protokol, cislo 0x11h znaci UDP (v dec 17)		x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)                                       x
			"%s, "				// Source IP/Zdrojova IP adresa                                                                     x
			"%s, " 				// Destination IP/Cilova IP adresa                                                                  x
			"%s, "				// Source port/Zdrojovy port                                                                        -
  			"const16(53), " 		// Destination - 53 is for DNS/Cilovy port 53 je pro DNS                                        UDP header
  			"const16(%u), "    		// UDP length/Delka UDP																			-
			"const16(0), "			// Checksum/Vypocet kontrolniho souctu (pre UDP je povolena 0)									-
			"drnd(2), "			// Transaction Identification/ID transakce pro dorucovani odpovedi									^
			"const16(0x0100), "		// Flags(Opcode) - standard query/Priznaky - standartni zadost	 								^
			"const16(1), "			// Question resource record count/Pocet zadosti v pakete									    DNS query message header	
			"const16(0), "			// Answer resource record count/Pocet odpovedi v pakete											^
			"const16(0), "			// Authority resource record count/Pocet autoritativnich DNS serveru							^
			"const16(0), "			// Additional resource record count/Doplnujici info												^
			"%s "				// Query name = Domain name (example.com)/DNS jmeno													|
			"0x00, "			// End of name (DNS name is encoded)/Ukonceni DNS jmena												|
			"const16(1), "			// Question type - A - host record/Typ otazky - A - zaznam o hostovi							DNS query fields
			"const16(1), "			// Question class - IN(Internet)/Trida otazky - IN(Internet)									|
			"fill(0x00, %u), "		// Filling/Vypln
			"}";

char *trafgen_dhcp_cfg = "{"
			"fill(0xff, 6), " 		 // Destination MAC address/Cilova MAC adresa                                                   /
			"0x9c, 0x4e, 0x36, drnd(3), "	//Source MAC address/Zdrojova MAC adresa												MAC header
			"const16(0x0800), " 		// 0x0800 is Ethertype for IPv4/Ethertype pro IPv4											/
			"0b01000101, 0, "		//IPv4 version (equal to 4), IHL (Inernet header length), ToS/IPv4 verze, IHL, ToS             	x
			"const16(%u), "			// Overall length of datagram/Celkova delka datagramu 											x
			"drnd(2), "			// IPv4 Identification 2B/IPv4 identifikace		                                                    x
			"0b01000000, 0, "		// IPv4 flags, don't fragment/IPv4 flags - nefragmentovat			                            x
			"64, "				// TTL (Time to Live)																				IP header
			"0x11, "			// Used protocol, 0x11 means UDP (17 in dec)/Pole protokol, cislo 0x11h znaci UDP (v dec 17)		x
			"csumip(14, 33), "		// Header Checksum/Vypocet kontrolniho souctu IP (od, do)                                       x
  			"0, 0, 0, 0, "			// Source IP/Zdrojova IP adresa                                                                 x
			"255, 255, 255, 255, "		// Destination IP/Cilova IP adresa                                                          x
			"const16(68), "			// Source port/Zdrojovy port                                                                    !
			"const16(67), "			// Destination/Cilovy port                                                                      !
			"const16(%u), "			// UDP length/Delka UDP																			UDP header
			"const16(0), "			// Checksum/Vypocet kontrolniho souctu (pre UDP je povolena 0)									!	
			"const8(0x01), "		// Opcode - value 0x01 is for Bootrequest/Typ zpravy											^
			"const8(0x01), "		// Hardware type - 0x01 is for Ethernet/HW typ													^
			"const8(0x06), "		// HW address length 8b - value 6 in dec/Delka HW adresy = 6 									^
			"const8(0x00), "		// Hop count - for relay agents/Pocet hopu - pro relay agenty 									^
			"drnd(4), "			// Transaction ID/ID transakce																		^
			"const16(0x00), "		// Number of seconds/Pocet ubehnutych sekund od zadosti											DHCP header	
			"const16(0x8000), "		// Flags - B for brcast/Priznaky (Broadcast)													^
			"0, 0, 0, 0, "			// Client IP address/IP adresa klienta															^
			"0, 0, 0, 0, "			// Your IP address/IP adresa klienta															^
			"0, 0, 0, 0, "			// Server IP address/IP adresa serveru															^
			"0, 0, 0, 0, "			// Gateway IP address/IP adresa GW																^
			"0x9c, 0x4e, 0x36, drnd(3), "   // Client HW address 16B long../MAC adresa klienta										^
			"fill(0x00, 202), "		// Optional parameters set to 0 (Sname,File)/Volitelne parametry + 10B z predesle MAC			|
			"const32(0x63825363), "		// DHCP magic cookie - to identify the information as vendor independent					|	
			"const8(0x35), "		// Code(Option) 53/Kod 53																		DHCP options
			"const8(0x01), "		// Length/Delka																					|
			"const8(0x01), "		// Type (1-8) - 1 = DHCP: Discover/Typ od 1 do 8												|
			"const8(0xff), "		// Ending/Ukonceni																				|
			"fill(0x00, %u), "		// Filling/Vypln
			"}";

#endif

