#pragma once

#include <stdint.h>
#include <string.h>
#include <linux/ip.h>
#include <arpa/inet.h>

/* Generic IP checksum (RFC 1071) */
static inline uint16_t checksum_generic(uint16_t *data, uint32_t len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)data;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* TCP/UDP pseudo-header checksum
 * Calling convention used by flood code:
 *   checksum_tcpudp(iph, transport_hdr, proto_len_network_order, data_len_host)
 * where iph is struct iphdr*, transport_hdr is the start of TCP/UDP header */
static inline uint16_t checksum_tcpudp(struct iphdr *iph, void *transport,
                                        uint16_t proto_len_net, uint16_t data_len) {
    uint32_t sum = 0;
    uint16_t *src = (uint16_t *)&iph->saddr;
    uint16_t *dst = (uint16_t *)&iph->daddr;
    uint16_t *d = (uint16_t *)transport;

    /* Pseudo-header: src IP, dst IP, zero+protocol, transport length */
    sum += src[0]; sum += src[1];
    sum += dst[0]; sum += dst[1];
    sum += htons(iph->protocol);
    sum += proto_len_net;

    /* Transport header + data */
    while (data_len > 1) {
        sum += *d++;
        data_len -= 2;
    }
    if (data_len == 1)
        sum += *(uint8_t *)d;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}
