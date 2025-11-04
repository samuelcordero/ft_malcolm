#ifndef __FT_MALCOLM_H__
# define __FT_MALCOLM_H__

# define BUF_SIZE 2048

# define USAGE_STR "Usage: %s <source_ip> <source_mac> <target_ip> <target_mac>\n"

# include "libft.h"

# include <net/if.h> 
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <netinet/ether.h>
# include <linux/if_packet.h>
# include <linux/if_arp.h>
# include <sys/socket.h>

struct arp_packet {
	struct arphdr hdr;
	unsigned char sender_mac[ETH_ALEN];
	unsigned char sender_ip[4];
	unsigned char target_mac[ETH_ALEN];
	unsigned char target_ip[4];
};

typedef struct s_malcolm
{
	char			*source_ip;
	char			*source_mac;
	char			*target_ip;
	char			*target_mac;
	unsigned char	source_mac_conv[6];
	unsigned char	target_mac_conv[6];
	struct in_addr	src_ip_conv;
	struct in_addr	dst_ip_conv;
}		t_malcolm;

// src/arp.c
void	send_arp_packet(int sock, const char *iface, t_malcolm *malcolm);

// src/parse.c
int		parse(int argc, char **argv, t_malcolm *malcolm);
int		parse_mac(const char *s, unsigned char *out);
int		parse_ip(const char *s, struct in_addr *out);

// src/utils.c
void	ft_clean_exit(int exit_code, int sock, void *buf);
void	print_arp_packet(const unsigned char *buf);

#endif