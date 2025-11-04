#include "ft_malcolm.h"

void	ft_clean_exit(int exit_code, int sock, void *buf) {
	if (sock != -1)
		close(sock);
	if (buf)
		free(buf);
	exit(exit_code);
}

void	print_arp_packet(const unsigned char *buf) {
	const struct ether_header *eth = (const struct ether_header *)buf;
	const struct arp_packet *arp = (const struct arp_packet *)(buf + sizeof(struct ether_header));

	printf("\n--- ETHERNET HEADER ---\n");
	printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("Source MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("EtherType:       0x%04x\n", ntohs(eth->ether_type));

	printf("\n--- ARP HEADER ---\n");
	printf("Hardware type:   %u\n", ntohs(arp->hdr.ar_hrd));
	printf("Protocol type:   0x%04x\n", ntohs(arp->hdr.ar_pro));
	printf("HW size:         %u\n", arp->hdr.ar_hln);
	printf("Proto size:      %u\n", arp->hdr.ar_pln);
	printf("Opcode:          %u (%s)\n",
		ntohs(arp->hdr.ar_op),
		ntohs(arp->hdr.ar_op) == 1 ? "request" :
		(ntohs(arp->hdr.ar_op) == 2 ? "reply" : "other"));

	printf("Sender MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
		arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
	printf("Sender IP:       %u.%u.%u.%u\n",
		arp->sender_ip[0], arp->sender_ip[1],
		arp->sender_ip[2], arp->sender_ip[3]);
	printf("Target MAC:      %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp->target_mac[0], arp->target_mac[1], arp->target_mac[2],
		arp->target_mac[3], arp->target_mac[4], arp->target_mac[5]);
	printf("Target IP:       %u.%u.%u.%u\n",
		arp->target_ip[0], arp->target_ip[1],
		arp->target_ip[2], arp->target_ip[3]);

	printf("------------------------\n\n");
}
