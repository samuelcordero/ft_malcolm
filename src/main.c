#include "ft_malcolm.h"

int main(int argc, char **argv) {
	t_malcolm	malcolm;

	if (parse(argc, argv, &malcolm)) {
		exit(EXIT_FAILURE);
	}

	int sock;
	unsigned char buffer[BUF_SIZE];
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);

	// Create raw socket to listen for ARP
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		perror("socket");
		ft_clean_exit(EXIT_FAILURE, -1, NULL);
	}

	printf("Listening for ARP packets...\n");

	while (1) {
		ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
							 (struct sockaddr *)&addr, &addr_len);
		if (n < 0) {
			perror("recvfrom");
			ft_clean_exit(EXIT_FAILURE, sock, NULL);
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

		if (!ft_strncmp(ether_ntoa((struct ether_addr *)arp->sender_mac), malcolm.target_mac, ft_strlen(malcolm.target_mac))
				&& !ft_strncmp(src_ip, malcolm.target_ip, ft_strlen(malcolm.target_ip))
				&& !ft_strncmp(dst_ip, malcolm.source_ip, ft_strlen(malcolm.source_ip))) {
			printf("\n=== ARP Packet Request from target ===\n");
			print_arp_packet(buffer);
			printf("===This one wants mango!===\n");

			printf("Building ARP packet...\n");
			send_arp_packet(sock, addr.sll_ifindex, &malcolm);
			break ;
		} else {
			printf("\n=== ARP Packet ===\n");
			print_arp_packet(buffer);
			printf("=== ARP Packet end ===\n");
		}
	}

	close(sock);
	return 0;
}
