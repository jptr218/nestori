#pragma once
#include "nestori.h"

struct ether_header
{
	uint8_t  dest[6];
	uint8_t  src[6];
	uint16_t type;
};

struct ip_hdr
{
	uint8_t ihl : 4;
	uint8_t ver : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;
	uint16_t len;
	uint16_t id;
	uint16_t fOff : 13;
	uint16_t flags : 3;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint8_t src[4];
	uint8_t dest[4];
};

struct udp_hdr {
	uint16_t src;
	uint16_t dest;
	uint16_t len;
	uint16_t csum;
};

struct dns_hdr {
	uint16_t tid;
	uint16_t flags;
	uint16_t qcount;
	uint16_t acount;
	uint16_t aucount;
	uint16_t adcount;
};

#pragma pack ( 1 )
struct dns_rcrd {
	uint16_t type;
	uint16_t clss;
	uint32_t ttl;
	uint16_t rdlen;
};