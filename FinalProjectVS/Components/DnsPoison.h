#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#ifndef DNSSPOOF_H
#define DNSSPOOF_H

#include <string>
#include <atomic>
#include <vector>
#include <iostream>
#pragma once
#include <unordered_set>
#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <pcap.h>
#include "SniffTraffic.h"



struct iface_info2 {
	ULONG ifIndex;
	std::string name;
	std::string description;
	uint8_t mac[6];
	uint8_t ip[4];
	uint8_t prefixlen;
	uint8_t gateway[4];
};

class DnsPoison {
public:
	std::atomic<bool> stop = false;
	std::string _ip;
	std::string victimip;
	std::string serverip;
	std::string urltopoison;
	pcap_t * handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[8];	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	u_char *user;
	const u_char *packet;	/* The actual packet */
	int packetcount;/* AMount of packets to capture*/
	int  AMOUNT_TO_CAPTURE = 100;

	//pcap_if_t **alldevsp;
	pcap_if_t * allAdapters;		//Used to store all the adapters in a list (by storing references to next adapters)


	DnsPoison(char* filter, int amounttocapture) :AMOUNT_TO_CAPTURE(amounttocapture)
	{
			strncpy_s(filter_exp, "port 53", sizeof(filter_exp));
	};
	static void fill_dns_packet(uint8_t* dnsspoofpacket, const uint8_t *packet);
	static void dothepoisoning(const uint8_t *packet, struct DnsRequest* check);
	//void fill_dns_packet(uint8_t dns_spoof_victim [] , std::string victimip, std::string serverip, std::string urltopoison);
	bool resolve(const iface_info2& iface, const uint8_t ip[4], uint8_t mac[6]);
	static void got_packet_dns(u_char * dumpfile, const pcap_pkthdr * header, const u_char * packet);
	int Capture();
	static void translatePacketToPayload(const u_char * packet);
	static void print_payload(const u_char *payload, int len);
	static void print_hex_ascii_line(const u_char *payload, int len, int offset);

};

#endif
#pragma once
