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
ULONG MacAddr[2];       /* for 6-byte hardware addresses */
void getMAC(char* SrcIpString, char* DestIpString)
{
	DWORD dwRetVal;
	IPAddr SrcIp = inet_addr(SrcIpString);
	IPAddr DestIp = inet_addr(DestIpString);
    //ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	BYTE *bPhysAddr;
	unsigned int i;
	memset(&MacAddr, 0xff, sizeof (MacAddr));

	printf("根据ARP协议获取主机MAC地址: %s\n", DestIpString);

	dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
	//cout << MacAddr << endl;

	//cout << PhysAddrLen << endl;
	if (dwRetVal == NO_ERROR) {
		cout << "主机MAC地址为：";
		bPhysAddr = (BYTE *) &MacAddr;
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
	//return MacAddr[2];
}