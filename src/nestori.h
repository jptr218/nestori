#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <pcap/pcap.h>
#include "packet.h"

#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

uint16_t checksum(uint16_t* buf, int sz);
string convertDomain(string v);
void strToIp(const char* s, uint8_t* ip);
vector<string> getDevices();

bool send_question(pcap_t* handle, uint8_t* dnssvr, string target, uint8_t* gateway);
bool send_answer(pcap_t* handle, uint8_t* dnssvr, string target, string s_targetns, uint8_t* targetns, uint8_t* ndest, uint8_t* gateway, uint16_t tid);