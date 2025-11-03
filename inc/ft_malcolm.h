#ifndef __FT_MALCOLM_H__
# define __FT_MALCOLM_H__

# define BUF_SIZE 2048

# include "libft.h"

struct arp_packet {
	struct arphdr hdr;
	unsigned char sender_mac[ETH_ALEN];
	unsigned char sender_ip[4];
	unsigned char target_mac[ETH_ALEN];
	unsigned char target_ip[4];
};

#endif