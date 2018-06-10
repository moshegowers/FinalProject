// http://www.troliver.com/?p=335

#pragma once
#define HAVE_REMOTE
typedef unsigned char u_char;

#include <pcap.h>
#include <Windows.h>

class SniffTraffic {
private:
	pcap_if_t * allAdapters;		//Used to store all the adapters in a list (by storing references to next adapters)
	pcap_if_t			*	adapter;			//Used to store one of the adapters in a list.
	pcap_t				*	captureInstance;	//Used to store a capture
	struct pcap_pkthdr	*	packetHeader;		//Used to store the header for a packet
	const u_char		*	packetData;			//Used to store the packet's data

	char errorBuffer[PCAP_ERRBUF_SIZE];

public:
	void Capture();
	bool TestTargetNetwork(pcap_if_t * adapter);
	int SniffByFilter(const char *packet_filter = "");
};
