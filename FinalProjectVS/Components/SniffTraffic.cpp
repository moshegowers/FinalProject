#include <Ws2tcpip.h>
#include "SniffTraffic.h"


//Capture code
void SniffTraffic::Capture()
{
	pcap_freealldevs(allAdapters);


	printf("\nCapture session started (%s)\n", adapter->name);


	int packetFound;
	while ((packetFound = pcap_next_ex(captureInstance, &packetHeader, &packetData)) >= 0)
	{
		if (packetFound == 0)
		{
			printf("\nPacket timed out! Trying again..");
			continue;
		}


		printf("\n%d:%d:%d length of packet: %d\n", (packetHeader->ts.tv_sec % 86400) / 3600, (packetHeader->ts.tv_sec % 3600) / 60, packetHeader->ts.tv_sec % 60, packetHeader->len);

		printf("\n");

		for (int x = 0; x < packetHeader->len; x++)
		{
			if ((packetData[x] == 0x0e) || (packetData[x] == '\0'))
			{
				printf("\n");
			}
			else
			{
				printf("%c", packetData[x]);
			}
		}
		//Stop iterating and exit
		break;
	}
}

//This is what we use to compare the interfaces against our network identity.
bool SniffTraffic::TestTargetNetwork(pcap_if_t * adapter)
{
	char ipAddress[INET6_ADDRSTRLEN];
	pcap_addr_t * adapterAddress;

	for (adapterAddress = adapter->addresses; adapterAddress; adapterAddress = adapterAddress->next)
	{
		if (adapterAddress->addr->sa_family == AF_INET)
		{
			InetNtop(adapterAddress->addr->sa_family,
				&(((struct sockaddr_in*)adapterAddress->addr)->sin_addr),
				ipAddress,
				sizeof(ipAddress));
		}
	}

	int hundreds;
	int tens;
	int units;

	if (ipAddress[2] == '.')
	{
		hundreds = (ipAddress[0] - '0') * 10;
		tens = (ipAddress[1] - '0') * 1;
		units = 0;
	}
	else
	{
		hundreds = (ipAddress[0] - '0') * 100;
		tens = (ipAddress[1] - '0') * 10;
		units = (ipAddress[2] - '0') * 1;
	}

	int temp4 = hundreds + tens + units;
	int network = 10;
	return (temp4 == network);
}

int SniffTraffic::SniffByFilter(const char *packet_filter)
{
	pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &allAdapters, errorBuffer);


	int totalAdapters = 0;

	for (adapter = allAdapters; adapter; adapter = adapter->next)
	{
		printf("\n%d %s) ", ++totalAdapters, adapter->name);
		printf("-- %s\n", adapter->description);
	}
	//Just add a blank line. Makes it look pretty.
	printf("\n");


	int selectedAdapterNumber = 0;

	for (adapter = allAdapters; adapter; adapter = adapter->next)
	{
		++selectedAdapterNumber;
		if (TestTargetNetwork(adapter))
		{
			printf("\nComputer is currently attached to the network through adapter %d", selectedAdapterNumber);
			printf("\n");
		}
	}

	adapter = allAdapters;
	for (int i = 0; i < selectedAdapterNumber - 1; i++)
	{
		adapter = adapter->next;
	}



	captureInstance = pcap_open(adapter->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 65000, NULL, errorBuffer);

	struct bpf_program fcode;
	pcap_compile(captureInstance, &fcode, packet_filter, 1, ((struct sockaddr_in *)(adapter->addresses->netmask))->sin_addr.S_un.S_addr);
	pcap_setfilter(captureInstance, &fcode);

	Capture();

	return 0;
}
