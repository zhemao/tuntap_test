#include "utils.h"

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	int fd;
	void *buf;
	long mac;
	char macstr[MAC_ADDR_SIZE * 3];

	if (argc < 2) {
		fprintf(stderr, "Usage: tap_pingd <ifname>\n");
		return EXIT_FAILURE;
	}

	buf = malloc(ETH_FRAME_MAX_SIZE);
	if (buf == NULL) {
		fprintf(stderr, "Could not allocate data\n");
		return EXIT_FAILURE;
	}

	srandom(time(NULL));
	mac = random();
	mactoa(macstr, (uint8_t *) &mac);

	printf("Using mac address %s\n", macstr);

	if ((fd = tuntap_alloc(argv[1], IFF_TAP | IFF_NO_PI)) < 0)
		abort();

	for (;;) {
		if (process_packet(fd, buf, (uint8_t *) &mac))
			return -1;
	}

	return 0;
}
