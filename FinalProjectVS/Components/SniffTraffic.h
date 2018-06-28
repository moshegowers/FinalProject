// http://www.troliver.com/?p=335

#pragma once
#define HAVE_REMOTE
typedef unsigned char u_char;

#include <pcap.h>
#include <Windows.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14


class SniffTraffic {
private:

	pcap_t * handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[8] = "port 53";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *user;
	const u_char *packet;	/* The actual packet */
	int packetcount;/* AMount of packets to capture*/
	int  AMOUNT_TO_CAPTURE = 100;
	

	//pcap_if_t **alldevsp;
	pcap_if_t * allAdapters;		//Used to store all the adapters in a list (by storing references to next adapters)
	//pcap_if_t			*	adapter;			//Used to store one of the adapters in a list.
	//pcap_t				*	captureInstance;	//Used to store a capture
	//struct pcap_pkthdr	*	packetHeader;		//Used to store the header for a packet
	//const u_char		*	packetData;			//Used to store the packet's data

	//char errorBuffer[PCAP_ERRBUF_SIZE];


	
public:
	pcap_dumper_t * dumpfile;
	char dumpfilename[40] = "C:\\Temp\\dump.pcap";
	SniffTraffic( const char * filter, int amounttocapture = 100);
	char* getDeviceName() { return dev; }
	static void got_packet(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *packet);
	static void translatePacketToPayload(const struct pcap_pkthdr *header, const u_char *packet);
	int Capture();
	static void print_payload(const u_char *payload, int len);
	static void print_hex_ascii_line(const u_char *payload, int len, int offset);
	
};
