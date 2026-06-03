#pragma once

#include <stdint.h>
#include <arpa/inet.h>

/* GRE header */
struct grehdr {
    uint16_t flags;
    uint16_t protocol;
};

/* GRE protocol types */
#define PROTO_GRE_TRANS_ETH 0x6558

/* TCP option kind bytes (both naming conventions) */
#define PROTO_tcpOPT_MSS   2
#define PROTO_tcpOPT_SACK  4
#define PROTO_tcpOPT_TSVAL 8
#define PROTO_tcpOPT_WSS   3
#define PROTO_TCP_OPT_MSS  2
#define PROTO_TCP_OPT_SACK 4
#define PROTO_TCP_OPT_TSVAL 8
#define PROTO_TCP_OPT_WSS  3

/* DNS structures */
struct dnshdr {
    uint16_t id;
    uint16_t opts;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

#define PROTO_DNS_QTYPE_A   1
#define PROTO_DNS_QCLASS_IP 1
