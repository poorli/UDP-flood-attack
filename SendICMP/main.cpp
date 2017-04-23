#include <winsock2.h>
#include "ping.h"

int total = 0;
int scanStartNum;
int scanEndNum;
struct sendICMPStruct
{
	int startScanIP;
	int endIP;
};

char sendIPsub[20] = "";

DWORD WINAPI hostScan(LPVOID lpParameter);
DWORD WINAPI hostScan(LPVOID lpParameter) {
	CPing objPing;
	sendICMPStruct *data = new sendICMPStruct();
	data = (sendICMPStruct*)lpParameter;
	for (int i = data->startScanIP; i < data->endIP; i++)
	{
		PingReply reply;
		char sendIP[20] = "";
		char tempStr[4] = "";
		_itoa_s(i, tempStr, 4, 10);
		strcat_s(sendIP, 20, sendIPsub);
		strcat_s(sendIP, 20, tempStr);
		objPing.Ping(sendIP, &reply);
		total++;
		//cout << "总共次数"<< total << endl;
		strcpy_s(sendIP, "");
	}
	return 0;
}
int main(void)
{
	CPing objPing;
	PingReply reply;
	//char *p;
	char *strDelim = ".";
	char startIP[] = "192.168.155.1";
	char endIP[] = "192.168.155.255";

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
			lastToken1 = token1;
			token1 = strtok_s(NULL, seps, &next_token1);
			
		}
		if (token2 != NULL)
		{
			tokenArr2[j] = atoi(token2);
			j++;
			lastToken2 = token2;
			token2 = strtok_s(NULL, seps, &next_token2);
		}
	}
	scanStartNum = atoi(lastToken1);
	scanEndNum = atoi(lastToken2);

	char sendIP[40] = "";
	char tempStr[4] = "";
	
	memset(sendIP, 0, sizeof(sendIP));
	memset(tempStr, 0, sizeof(tempStr));
	for (i = 0; i < 3; i++)
	{
		_itoa_s(tokenArr1[i], tempStr, 4, 10);
		strcat_s(sendIPsub, sizeof(sendIPsub) + sizeof(tempStr) + sizeof("\0"), tempStr);
		strcat_s(sendIPsub, sizeof(sendIPsub)+sizeof(tempStr)+sizeof("\0"), ".");
	}
	int step = 10;
	int threadCount = 0;

	HANDLE *hThread;
	hThread = NULL;
	time_t startTime = time(0), endTime;
	for (int i = 1; i < scanEndNum; i = i + step)
	{

		sendICMPStruct *icmpData = new sendICMPStruct();
		icmpData->startScanIP = i;
		if (i + step > scanEndNum)
		{
			icmpData->endIP = scanEndNum;
		}
		else {
			icmpData->endIP = i + step;
		}
		DWORD dwThreadId;
		hThread = (HANDLE *)realloc(hThread, sizeof(HANDLE)*threadCount);
		hThread[threadCount] = CreateThread(NULL, 0, hostScan, icmpData, NULL, &dwThreadId);
		//Sleep(1000);
		threadCount++;
		Sleep(50);
	}
	//最后一次处理
	_itoa_s(scanEndNum, tempStr, 4, 10);
	strcat_s(sendIP, sizeof(sendIP)+sizeof(sendIPsub)+sizeof("\0"), sendIPsub);
	strcat_s(sendIP, sizeof(sendIP)+sizeof(tempStr)+sizeof("\0"), tempStr);
	objPing.Ping(sendIP, &reply);
	endTime = time(0);
	WaitForMultipleObjects(threadCount, hThread, TRUE, INFINITE);

	while (true){
		if (total == scanEndNum - 1)
		{
			break;
		}
	}

	cout << "主机扫描结果：" << endl;
	//map<string, int>::iterator tempMap;
	strcpy_s(sendIP, "");
	for (int i = scanStartNum ; i <= scanEndNum; i++)
	{
		_itoa_s(i, tempStr, 4, 10);
		strcat_s(sendIP, sizeof(sendIP)+sizeof(sendIPsub)+sizeof("\0"), sendIPsub);
		strcat_s(sendIP, sizeof(sendIP)+sizeof(tempStr)+sizeof("\0"), tempStr);
		if (hostScanStatus.find(sendIP) != hostScanStatus.end())
		{
			cout << "主机" << sendIP << "开放" << endl;
		}
		strcpy_s(sendIP, "");
	}
	//for (int i = scanStartNum; i <= scanEndNum; i++)
	//{
	//	_itoa_s(i, tempStr, 4, 10);
	//	strcat_s(sendIP, 20, sendIPsub);
	//	strcat_s(sendIP, 20, tempStr);
	//	objPing.Ping(sendIP, &reply);
	//	strcpy_s(sendIP, "");
	//}
	cout << endTime - startTime << endl;
	cout << "end" << endl;
	cout << "扫描次数为：" << total<<endl;
	/*printf("Pinging %s with %d bytes of data:\n", szDestIP, DEF_PACKET_SIZE);*/
	//while (TRUE)
	//{
	//	objPing.Ping(szDestIP, &reply);
	//	objPing.Ping(szDestIP, &reply);
	//	printf("Reply from %s: bytes=%d time=%ldms TTL=%ld\n", szDestIP, reply.m_dwBytes, reply.m_dwRoundTripTime, reply.m_dwTTL);
	//	Sleep(500);
	//}
	//return 0;
	//system("pasue");
	system("pause");
}