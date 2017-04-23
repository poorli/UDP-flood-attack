#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
using namespace std;

#include <map>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

void usage(char *pname)
{
	printf("Usage: %s [options] ip-address\n", pname);
	printf("\t -h \t\thelp\n");
	printf("\t -l length \tMAC physical address length to set\n");
	printf("\t -s src-ip \tsource IP address\n");
	exit(1);
}

int main()
{
	DWORD dwRetVal;
	IPAddr DestIp = 0;
	IPAddr SrcIp = 0;       /* default for src ip */
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	char *DestIpString = NULL;
	char *SrcIpString = NULL;

	BYTE *bPhysAddr;
	unsigned int i;
	//SrcIpString = "10.21.8.73";
	//SrcIpString = "10.26.30.193";
	SrcIpString = "192.168.155.1";
	//DestIpString = "192.168.155.2";
	DestIpString = "192.168.155.2";
	//SrcIpString = "172.16.24.233";
	//SrcIpString = "172.26.27.209";
	SrcIp = inet_addr(SrcIpString);
	//DestIpString = "123.206.80.223";
	//DestIpString = "111.13.101.208";
	//DestIpString = "10.211.55.4";

	DestIp = inet_addr(DestIpString);

	memset(&MacAddr, 0xff, sizeof (MacAddr));

	printf("Sending ARP request for IP address: %s\n", DestIpString);

	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
	cout << MacAddr << endl;
	cout << PhysAddrLen<< endl;
	char arp[20];
	if (dwRetVal == NO_ERROR) {
		//cout << "a" << endl;
		bPhysAddr = (BYTE *)& MacAddr;
		memcpy(arp, &MacAddr, sizeof(MacAddr));
		cout << arp << endl;
		//cout <<"bphysAddr:"<< bPhysAddr << endl;
		if (PhysAddrLen) {
			for (i = 0; i < (int)PhysAddrLen; i++) {
				if (i == (PhysAddrLen - 1))
				{
					printf("%.2X\n", (int)bPhysAddr[i]);
					(INT16)bPhysAddr[i];

				}
					
				else
				{
					printf("%.2X-", (int)bPhysAddr[i]);
					(INT16)bPhysAddr[i];
				}
					
			}
		}
		else
			printf
			("Warning: SendArp completed successfully, but returned length=0\n");

	}
	else {
		printf("Error: SendArp failed with error: %d", dwRetVal);
		switch (dwRetVal) {
		case ERROR_GEN_FAILURE:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf(" (ERROR_INVALID_PARAMETER)\n");
			break;
		case ERROR_INVALID_USER_BUFFER:
			printf(" (ERROR_INVALID_USER_BUFFER)\n");
			break;
		case ERROR_BAD_NET_NAME:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_BUFFER_OVERFLOW:
			printf(" (ERROR_BUFFER_OVERFLOW)\n");
			break;
		case ERROR_NOT_FOUND:
			printf(" (ERROR_NOT_FOUND)\n");
			break;
		default:
			printf("\n");
			break;
		}
	}
	system("pause");
}
