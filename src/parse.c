#include "ft_malcolm.h"

int	parse(int argc, char **argv, t_malcolm *malcolm) {
	malcolm->source_ip = argv[1];
	malcolm->source_mac = argv[2];
	malcolm->target_ip = argv[3];
	malcolm->target_mac = argv[4];

	if (argc != 5) {
		fprintf(stderr, USAGE_STR, argv[0]);
		return -1;
	}

	if (parse_ip(malcolm->source_ip, &malcolm->src_ip_conv) == -1) {
		fprintf(stderr, "Invalid IP format: %s\n", malcolm->source_ip);
		return -1;
	}

	if (parse_ip(malcolm->target_ip, &malcolm->dst_ip_conv) == -1) {
		fprintf(stderr, "Invalid IP format: %s\n", malcolm->target_ip);
		return -1;
	}

	if (parse_mac(malcolm->source_mac, malcolm->source_mac_conv) == -1) {
		fprintf(stderr, "Invalid MAC format: %s\n", malcolm->source_mac);
		return -1;
	}

	if (parse_mac(malcolm->target_mac, malcolm->target_mac_conv) == -1) {
		fprintf(stderr, "Invalid MAC format: %s\n", malcolm->target_mac);
		return -1;
	}
	return 0;
}

int	parse_mac(const char *s, unsigned char *out) {
	unsigned char	vals[6];
	char			tail[2];
	int				matched;

	if (s == NULL || out == NULL)
		return -1;

	matched = sscanf(s, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx%1s",
				&vals[0], &vals[1], &vals[2],
				&vals[3], &vals[4], &vals[5],
				tail);

	if (matched != 6) // check for no trailing chars
		return -1;

	int	all_zero = 1;
	int	all_ff = 1;
	for (int i = 0; i < 6; i++) {
		out[i] = vals[i];
		if (vals[i] != 0x00)
			all_zero = 0;
		if (vals[i] != 0xFF) 
			all_ff = 0;
	}

	if (all_zero || all_ff)
		return -1;

	return 0;
}

int	parse_ip(const char *s, struct in_addr *out) {
	unsigned int	o1, o2, o3, o4;
	char			tail[2];
	int				matched;

	if (s == NULL || out == NULL)
		return -1;

	matched = sscanf(s, "%3u.%3u.%3u.%3u%1s", &o1, &o2, &o3, &o4, tail);
	if (matched != 4)
		return -1;

	if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255) //valid octet check
		return -1;

	if (inet_aton(s, out) == 0)
		return -1;

	if (out->s_addr == htonl(0x00000000) || out->s_addr == htonl(0xFFFFFFFF)) //no full 0s/Fs
		return -1;

	return 0;
}
