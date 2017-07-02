#ifndef TUNTAP_UTIL_H
#define TUNTAP_UTIL_H

#define ETH_FRAME_MAX_SIZE 1522
#define NET_IP_ALIGN 2
#define ETH_HEADER_SIZE 14
#define MAC_ADDR_SIZE 6
#define IP_ADDR_SIZE 4

#define IPV4_ETHTYPE 0x0800
#define ARP_ETHTYPE 0x0806
#define ICMP_PROT 1
#define ECHO_REPLY 0
#define ECHO_REQUEST 8
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define HTYPE_ETH 1

#include <stdint.h>

int tuntap_alloc(const char *dev, int flags);
int process_packet(int fd, void *buf, uint8_t *mac);
void mactoa(char *str, uint8_t *mac);

#endif
