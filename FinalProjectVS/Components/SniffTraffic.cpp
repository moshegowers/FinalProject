#include <Ws2tcpip.h>
#include "SniffTraffic.h"


SniffTraffic::SniffTraffic(char* filter, int amounttocapture) :AMOUNT_TO_CAPTURE(amounttocapture)
{
	if (filter != NULL)
	{
		strncpy_s(filter_exp, filter, sizeof(filter_exp));
	}
}

void SniffTraffic::got_packet(u_char * dumpfile, const pcap_pkthdr * header, const u_char * packet)
{
	/* save the packet on the dump file */
	pcap_dump(dumpfile, header, packet);
	translatePacketToPayload(header, packet);
}

//Capture code
int SniffTraffic::Capture()
{
	/* find all the devices and use the first one*/
	int error =  pcap_findalldevs(&allAdapters, errbuf);
								/* Define the device */
	/*dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}*/
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
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */

	


	/* At this point, we no longer need the device list. Free it */
	pcap_freealldevs(allAdapters);

	/* Open the dump file */
	dumpfile = pcap_dump_open(handle, dumpfilename);
	/*
	start a loop fo capture. each packet sent to got_packet cllback function
	*/
	printf("start Capturing...\n");
	pcap_loop(handle, AMOUNT_TO_CAPTURE, got_packet, (unsigned char *)dumpfile);
	printf("\nCapturing finished");
	/* And close the session */
	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	return(0);
}

//This is what we use to compare the interfaces against our network identity.


void SniffTraffic::translatePacketToPayload(const pcap_pkthdr * header, const u_char * packet)
{
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		//return;
	}
	payload = (packet + SIZE_ETHERNET + size_ip + size_tcp);
	print_payload(payload, SIZE_ETHERNET + size_ip + size_tcp);
}

/*
* print packet payload data (avoid printing binary data)
*/
void SniffTraffic::print_payload(const u_char *payload, int len)
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
void SniffTraffic::print_hex_ascii_line(const u_char * payload, int len, int offset)
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
