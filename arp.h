#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include <iostream>
using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int getMAC()
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
	//SrcIpString = "10.26.30.193";
	SrcIpString = "10.26.30.193";
	//SrcIpString = "192.168.0.1";
	SrcIp = inet_addr(SrcIpString);
	DestIpString = "123.206.80.223";
	//DestIpString = "111.13.101.208";

	DestIp = inet_addr(DestIpString);

	memset(&MacAddr, 0xff, sizeof (MacAddr));

	printf("Sending ARP request for IP address: %s\n", DestIpString);

	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
	cout << MacAddr << endl;

	cout << PhysAddrLen << endl;
	if (dwRetVal == NO_ERROR) {
		//cout << "a" << endl;
		bPhysAddr = (BYTE *)& MacAddr;
		//cout <<"bphysAddr:"<< bPhysAddr << endl;
		if (PhysAddrLen) {
			for (i = 0; i < (int)PhysAddrLen; i++) {
				if (i == (PhysAddrLen - 1))
					printf("%.2X\n", (int)bPhysAddr[i]);
				else
					printf("%.2X-", (int)bPhysAddr[i]);
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