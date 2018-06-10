#pragma once

#ifndef ARPSPOOF_H
#define ARPSPOOF_H

#include <string>
#include <atomic>
#include <vector>
#include <unordered_set>
#include <winsock2.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <pcap.h>
#include <Windows.h>


struct iface_info {
	ULONG ifIndex;
	std::string name;
	std::string description;
	uint8_t mac[6];
	uint8_t ip[4];
	uint8_t prefixlen;
	uint8_t gateway[4];
};

class Arpspoof {
public:
	void handle_packet(pcap_t *pcap, pcap_pkthdr *header, const uint8_t *data, const uint8_t *victim_mac, const uint8_t *victim_ip,
		const uint8_t *target_mac, const uint8_t *my_mac);
	void fill_arp_packet(uint8_t *packet, const uint8_t *victim_ip, const uint8_t *victim_mac, const uint8_t *my_ip, const uint8_t *my_mac);
	std::string unicode_to_str(wchar_t *unistr);
	std::string ip_to_str(const uint8_t ip[4]);
	std::string mac_to_str(const uint8_t mac[6]);
	std::vector<iface_info> find_ifaces();
	void print_ifaces(const std::vector<iface_info>& ifaces);
	bool resolve(const iface_info& iface, const uint8_t ip[4], uint8_t mac[6]);

	std::atomic<bool> stop;
	BOOL WINAPI CtrlCHandler(DWORD dwCtrlType) {
		if (dwCtrlType == CTRL_C_EVENT) {
			stop = true;
			return TRUE;
		}
		return FALSE;
	}
};

#endif
