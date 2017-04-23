#include <winsock2.h>
#include <stdio.h>
#include "ping.h"

int main(void)
{
	CPing objPing;
	//char *szDestIP = "123.206.80.223";
	PingReply reply;
	char *szDestIP = "192.168.155.2";
	
	string desIP = "192.168.155.1";

	char *p;
	char *strDelim = ".";
	//char *next_token = NULL;
	
	char startIP[] = "192.168.155.1";
	char endIP[] = "192.168.155.20";
	int scanStartNum;
	int scanEndNum;
	
	char string1[] = "192.168.155.2";
	char string2[] = "192.168.155.50";
	char seps[] = ".";
	char *token1 = NULL;
	char *token2 = NULL;
	char *lastToken1 = NULL;
	int tokenArr1[4];
	int tokenArr2[4];
	char *lastToken2 = NULL;
	char *next_token1 = NULL;
	char *next_token2 = NULL;

	token1 = strtok_s(startIP, seps, &next_token1);
	token2 = strtok_s(endIP, seps, &next_token2);

	int i = 0, j = 0;
	while ((token1 != NULL) || (token2 != NULL))
	{
		// Get next token:  
		if (token1 != NULL)
		{
			tokenArr1[i] = atoi(token1);
			i++;
			printf(" %s\n", token1);
			lastToken1 = token1;
			token1 = strtok_s(NULL, seps, &next_token1);
			
		}
		if (token2 != NULL)
		{
			tokenArr2[j] = atoi(token2);
			j++;
			printf(" %s\n", token2);
			lastToken2 = token2;
			token2 = strtok_s(NULL, seps, &next_token2);
		}
	}
	scanStartNum = atoi(lastToken1);
	scanEndNum = atoi(lastToken2);

	char sendIP[20] = "";
	char sendIPsub[20] = "";
	char tempStr[4] = "";
	for (i = 0; i < 3; i++)
	{
		_itoa_s(tokenArr1[i], tempStr, 4, 10);
		strcat_s(sendIPsub, 20, tempStr);
		strcat_s(sendIPsub, 20, ".");
	}
	
	for (int i = scanStartNum; i <= scanEndNum; i++)
	{
		_itoa_s(i, tempStr, 4, 10);
		strcat_s(sendIP, 20, sendIPsub);
		strcat_s(sendIP, 20, tempStr);
		objPing.Ping(sendIP, &reply);
		//sendIP[20] = "";
		strcpy_s(sendIP, "");
		Sleep(50);
	}

	cout << "end" << endl;
	/*printf("Pinging %s with %d bytes of data:\n", szDestIP, DEF_PACKET_SIZE);*/
	//while (TRUE)
	//{
	//	objPing.Ping(szDestIP, &reply);
	//	objPing.Ping(szDestIP, &reply);
	//	printf("Reply from %s: bytes=%d time=%ldms TTL=%ld\n", szDestIP, reply.m_dwBytes, reply.m_dwRoundTripTime, reply.m_dwTTL);
	//	Sleep(500);
	//}
	//return 0;
}