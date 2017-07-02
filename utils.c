#include "utils.h"

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/if_tun.h>

struct eth_header {
	uint8_t padding[NET_IP_ALIGN];
	uint8_t dst_mac[MAC_ADDR_SIZE];
	uint8_t src_mac[MAC_ADDR_SIZE];
	uint16_t ethtype;
};

struct arp_header {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t oper;
	uint8_t sha[MAC_ADDR_SIZE];
	uint8_t spa[IP_ADDR_SIZE];
	uint8_t tha[MAC_ADDR_SIZE];
	uint8_t tpa[IP_ADDR_SIZE];
};

struct ipv4_header {
	uint8_t ver_ihl;
	uint8_t dscp_ecn;
	uint16_t length;
	uint16_t ident;
	uint16_t flags_frag_off;
	uint8_t ttl;
	uint8_t prot;
	uint16_t cksum;
	uint32_t src_addr;
	uint32_t dst_addr;
};

struct icmp_header {
	uint8_t type;
	uint8_t code;
	uint16_t cksum;
	uint32_t rest;
};

int tuntap_alloc(const char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("open()");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
		perror("ioctl()");
		close(fd);
		return err;
	}

	return fd;
}

static int checksum(uint16_t *data, int len)
{
	int i;
	uint32_t sum = 0;

	for (i = 0; i < len; i++)
		sum += ntohs(data[i]);

	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = ~sum & 0xffff;

	return sum;
}

static int process_arp(int fd, void *buf, uint8_t *mac)
{
	struct eth_header *eth = buf;
	struct arp_header *arp;
	ssize_t size = ETH_HEADER_SIZE + sizeof(*arp);
	uint8_t tmp_addr[IP_ADDR_SIZE];

	// Verify arp packet
	arp = buf + sizeof(*eth);
	if (ntohs(arp->oper) != ARP_REQUEST) {
		fprintf(stderr, "Wrong arp operation: %d\n", ntohs(arp->oper));
		return -1;
	}

	if (ntohs(arp->htype) != HTYPE_ETH) {
		fprintf(stderr, "Wrong ARP HTYPE\n");
		return -1;
	}

	if (ntohs(arp->ptype) != IPV4_ETHTYPE) {
		fprintf(stderr, "Wrong ARP PTYPE\n");
		return -1;
	}

	if (arp->hlen != 6) {
		fprintf(stderr, "Wrong ARP HLEN: %d\n", arp->hlen);
		return -1;
	}

	if (arp->plen != 4) {
		fprintf(stderr, "Wrong ARP PLEN: %d\n", arp->plen);
		return -1;
	}

	// Make the source the destination, and add our mac address
	memcpy(eth->dst_mac, eth->src_mac, MAC_ADDR_SIZE);
	memcpy(eth->src_mac, mac, MAC_ADDR_SIZE);

	// create ARP reply
	arp->oper = htons(ARP_REPLY);

	// Make tha the sha, and fill in sha with actual mac address
	memcpy(arp->tha, arp->sha, MAC_ADDR_SIZE);
	memcpy(arp->sha, mac, MAC_ADDR_SIZE);

	// Swap spa and tpa in arp packet
	memcpy(tmp_addr, arp->tpa, IP_ADDR_SIZE);
	memcpy(arp->tpa, arp->spa, IP_ADDR_SIZE);
	memcpy(arp->spa, tmp_addr, IP_ADDR_SIZE);

	if (write(fd, buf + NET_IP_ALIGN, size) < 0) {
		perror("write()");
		return -1;
	}

	return 0;
}
static int process_icmp(int fd, void *buf, uint8_t *mac)
{
	struct eth_header *eth = buf;
	struct ipv4_header *ipv4;
	struct icmp_header *icmp;
	int ihl, icmp_size;
	ssize_t size;
	uint32_t tmp_addr;

	// verify IPv4
	ipv4 = buf + sizeof(*eth);
	ihl = ipv4->ver_ihl & 0xf;

	if (checksum((uint16_t *) ipv4, ihl << 1) != 0) {
		fprintf(stderr, "Bad IP header checksum %04x\n", ipv4->cksum);
		return -1;
	}

	if (ipv4->prot != ICMP_PROT) {
		fprintf(stderr, "Wrong IP protocol %d\n", ipv4->prot);
		return -1;
	}

	// verify ICMP
	icmp = (buf + sizeof(*eth) + (ihl << 2));

	if (icmp->type != ECHO_REQUEST) {
		fprintf(stderr, "Wrong ICMP type %d\n", icmp->type);
		return -1;
	}

	if (icmp->code != 0) {
		fprintf(stderr, "Wrong ICMP code %d\n", icmp->code);
		return -1;
	}

	icmp_size = ntohs(ipv4->length) - (ihl << 2);
	if (checksum((uint16_t *) icmp, icmp_size >> 1) != 0) {
		fprintf(stderr, "Bad ICMP checksum %04x\n", icmp->cksum);
		return -1;
	}

	// Set the destination and source MACs
	memcpy(eth->dst_mac, eth->src_mac, MAC_ADDR_SIZE);
	memcpy(eth->src_mac, mac, MAC_ADDR_SIZE);

	// Swap the source and destination IP addresses
	tmp_addr = ipv4->dst_addr;
	ipv4->dst_addr = ipv4->src_addr;
	ipv4->src_addr = tmp_addr;

	// compute the IPv4 header checksum
	ipv4->cksum = 0;
	ipv4->cksum = htons(checksum((uint16_t *) ipv4, ihl << 1));

	// set the ICMP type to reply and compute checksum
	icmp->cksum = 0;
	icmp->type = ECHO_REPLY;
	icmp->cksum = htons(checksum((uint16_t *) icmp, icmp_size >> 1));
	size = ntohs(ipv4->length) + ETH_HEADER_SIZE;

	if (write(fd, buf + NET_IP_ALIGN, size) < 0) {
		perror("write()");
		return -1;
	}

	return 0;
}

int process_packet(int fd, void *buf, uint8_t *mac)
{
	ssize_t size;
	struct eth_header *eth;

	// read the ICMP request
	size = read(fd, buf + NET_IP_ALIGN, ETH_FRAME_MAX_SIZE);
	if (size < 0) {
		perror("read()");
		return -1;
	}

	eth = buf;
	printf("Got packet: [ethtype=%04x, size=%ld]\n",
			ntohs(eth->ethtype), size);
	// Check ethernet type
	switch (ntohs(eth->ethtype)) {
	case IPV4_ETHTYPE:
		return process_icmp(fd, buf, mac);
	case ARP_ETHTYPE:
		return process_arp(fd, buf, mac);
	default:
		fprintf(stderr, "Wrong ethtype %x\n", ntohs(eth->ethtype));
		return -1;
	}
}

void mactoa(char *str, uint8_t *mac)
{
	int i, len;

	len = sprintf(str, "%02x", mac[0]);
	str += len;

	for (i = 1; i < MAC_ADDR_SIZE; i++) {
		len = sprintf(str, ":%02x", mac[i]);
		str += len;
	}
}
