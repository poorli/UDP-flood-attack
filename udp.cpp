#include "udpScan.h"
#include "arp.h"
#include <ctime>
#include "ping.h"

//ѡ�������
//char SourceIP[16];
//char SourcePort[6];
//char SourceMAC[19];
//
//char DestinationIP[16];
//char DestinationPort[6];
//char DataString[2048];
////strcpy_s(SourceIP, "-1");
////strcpy_s(SourceIP, "10.26.32.23");
////strcpy_s(SourceIP, "10.21.8.73");
//strcpy_s(SourceIP, "10.26.30.193");
//strcpy_s(SourcePort, "56921");
//strcpy_s(SourceMAC, "-1");
//strcpy_s(DestinationIP, "123.206.80.223");
////strcpy_s(DestinationIP, "123.206.80.225");
////strcpy_s(DestinationIP, "255.255.255.255");
////strcpy_s(DestinationIP, "192.168.0.1");
////strcpy_s(DestinationIP, "localhost");
////strcpy_s(DestinationIP, "127.0.0.1");
//strcpy_s(DestinationPort, "8888");
//strcpy_s(DataString, "hello");
//unsigned char desMAC[6];
int hostThreadScanTimes = 0;
int hostScanStartPort;
int hostScanEndPort;
struct sendICMPStruct
{
	int startScanIP;
	int endIP;
};
char sendIPsub[20] = "";

DWORD WINAPI hostScan(LPVOID lpParameter);

int main()
{
	ShowDeviceList();
	cout << "ѡ�����أ�" << endl;
	int chosen;
	cin >> chosen;
	getChoicedDevice(chosen);
	//diΪ����������Ϣ
	DeviceInfo di;
	di = GetAdapterInfo(ChosenDevice);
	if (di.Exists == false)
	{
		cout << "Invalid Selection (Try another device)\n";
		return 0;
	}
	cout << "ѡ������Ϊ�� " << ChosenDevice->name << endl;

	CPing objPing;
	PingReply reply;
	/*char startIP[] = "123.206.80.223.1";
	char endIP[] = "192.168.155.255";*/
	//char startIP[] = "123.206.80.223.1";
	//char endIP[] = "123.206.80.223.255"
	char startIP[40];
	char endIP[40];
	cout << "����ɨ��" << endl;
	cout << "��ʼIP��";
	cin >> startIP;
	cout << "�յ�IP��";
	cin >> endIP;
	//����IP��ַ
	char *strDelim = ".";
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
	int i = 0;
	int j = 0;

	while ((token1 != NULL) || (token2 != NULL))
	{
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
	//��ʼ��ɨ��IP��ʼֻ���յ�ֵ
	hostScanStartPort = atoi(lastToken1);
	hostScanEndPort = atoi(lastToken2);

	char sendIP[40] = "";
	char tempStr[4] = "";
	memset(sendIP, 0, sizeof(sendIP));
	memset(tempStr, 0, sizeof(tempStr));

	//��ȡ����ǰ׺
	for (i = 0; i < 3; i++)
	{
		_itoa_s(tokenArr1[i], tempStr, 4, 10);
		strcat_s(sendIPsub, sizeof(sendIPsub)+sizeof(tempStr)+sizeof("\0"), tempStr);
		strcat_s(sendIPsub, sizeof(sendIPsub)+sizeof(tempStr)+sizeof("\0"), ".");
	}

	//�ֶ�ɨ��������stepΪÿ���߳�ɨ�����������ɵ����Ż�ɨ��ʱ��
	int step = 10;
	int threadCount = 0;
	HANDLE *hThread;
	hThread = NULL;
	//time_t startTime = time(0), endTime;
	cout << "��ʼ����ɨ�裺" << endl;
	for (int i = 1; i < hostScanEndPort; i = i + step)
	{
		sendICMPStruct *icmpData = new sendICMPStruct();
		icmpData->startScanIP = i;

		if (i + step > hostScanEndPort)
		{
			icmpData->endIP = hostScanEndPort;
		}
		else {
			icmpData->endIP = i + step;
		}

		DWORD dwThreadId;
		hThread = (HANDLE *)realloc(hThread, sizeof(HANDLE)*threadCount);
		hThread[threadCount] = CreateThread(NULL, 0, hostScan, icmpData, NULL, &dwThreadId);

		threadCount++;
		Sleep(10);
	}
	//���һ�δ���
	_itoa_s(hostScanEndPort, tempStr, 4, 10);
	strcat_s(sendIP, sizeof(sendIP)+sizeof(sendIPsub)+sizeof("\0"), sendIPsub);
	strcat_s(sendIP, sizeof(sendIP)+sizeof(tempStr)+sizeof("\0"), tempStr);
	objPing.Ping(sendIP, &reply);
	//endTime = time(0);
	WaitForMultipleObjects(threadCount, hThread, TRUE, INFINITE);

	//���̵߳ȴ���������ɨ���߳̽���
	while (true){
		if (hostThreadScanTimes == hostScanEndPort - 1)
		{
			break;
		}
	}

	cout << "����ɨ������" << endl;
	//map<string, int>::iterator tempMap;
	strcpy_s(sendIP, "");
	for (int i = hostScanStartPort; i <= hostScanEndPort; i++)
	{
		_itoa_s(i, tempStr, 4, 10);
		strcat_s(sendIP, sizeof(sendIP)+sizeof(sendIPsub)+sizeof("\0"), sendIPsub);
		strcat_s(sendIP, sizeof(sendIP)+sizeof(tempStr)+sizeof("\0"), tempStr);
		if (existHostMap.find(sendIP) != existHostMap.end())
		{
			cout << sendIP << "	����" << endl;
		}
		strcpy_s(sendIP, "");
	}

	char choicedScanIP[20];
	cout << "ѡ������IP��";

	while (true)
	{
		cin >> choicedScanIP;
		if (existHostMap.find(choicedScanIP) != existHostMap.end())
		{
			cout << "ѡ������IPΪ��" << choicedScanIP << endl;
			break;
		}
		else
		{
			cout << "������δ���ţ�����ѡ��˿ڣ�";
		}
	}

	//cout << endTime - startTime << endl;
	//cout << "end" << endl;
	//cout << "ɨ�����Ϊ��" << hostThreadScanTimes << endl;
	//desMAC[0] = 0x58;
	//desMAC[1] = 0x97;
	//desMAC[2] = 0xbd;
	//desMAC[3] = 0x5b;
	//desMAC[4] = 0x4b;
	//desMAC[5] = 0x80;

	//��ʼ����������
	char SourceIP[16];
	char SourcePort[6];
	char SourceMAC[19];
	char DestinationIP[16];
	char DestinationPort[6];
	char DataString[2048];
	//strcpy_s(SourceIP, "-1");
	//strcpy_s(SourceIP, "124.207.89.110");
	//strcpy_s(SourceIP, "10.26.30.193");
	strcpy_s(SourceIP, "192.168.155.1");
	strcpy_s(SourcePort, "56921");
	strcpy_s(SourceMAC, "-1");
	//strcpy_s(DestinationIP, "123.206.80.223");
	strcpy_s(DestinationIP, "192.168.155.2");
	//strcpy_s(DestinationIP, "123.206.80.225");
	//strcpy_s(DestinationIP, "255.255.255.255");
	//strcpy_s(DestinationIP, "192.168.0.1");
	//strcpy_s(DestinationIP, "localhost");
	//strcpy_s(DestinationIP, "127.0.0.1");
	strcpy_s(DestinationPort, "8888");
	strcpy_s(DataString, "hello");

	unsigned char desMAC[6];
	//��ȡMAC��ַ����ȫ�ֱ���ULONG MacAddr[2]��
	//cout << "����IP��ַ����192.168.xxx.xxx����";
	while (true)
	{
		cin >> DestinationIP;
		if (getMAC(SourceIP, DestinationIP) == FALSE)
		{
			cout << "��ȡMAC��ַʧ��,��������ȷ��IP��" << endl;
			continue;
		}
		else
		{
			BYTE *bPhysAddr;
			bPhysAddr = (BYTE *)&MacAddr;
			for (i = 0; i < (int)6; i++) {
				desMAC[i] = (int)bPhysAddr[i];
			}
			break;
		}
	}

	//��ʼ��udpScan()�������udpScanData
	ThreadParamStruct *udpScanData = new ThreadParamStruct();
	udpScanData->ChosenDevice = ChosenDevice;
	strcpy_s(udpScanData->SourceMAC, SourceMAC);
	strcpy_s(udpScanData->SourceIP, SourceIP);
	strcpy_s(udpScanData->SourcePort, SourcePort);
	memcpy(udpScanData->desMAC, desMAC, sizeof(desMAC));
	strcpy_s(udpScanData->DestinationIP, DestinationIP);
	udpScanData->di = di;
	strcpy_s(udpScanData->DataString, DataString);

	//udpScanData->SourceMAC = SourceMAC;
	//udpScanData->SourceIP = SourceIP;
	//cout << "Enter source IP (or -1 for real)\n";
	//cin >> SourceIP;
	//cout << "Enter source port (0-65535)\n";
	//cin >> SourcePort;
	//cout << "Enter source MAC (or -1 for real) \n";
	//cin >> SourceMAC;
	//cout << "Enter destination IP\n";
	//cin >> DestinationIP;
	//cout << "Enter destination port(0-65535)\n";
	//cin >> DestinationPort;
	//cout << "Enter data string\n";
	//cin >> DataString;
	

	//����ICMP�˿ڲ��ɴ�����߳�
	ThreadICMP *ICMP = new ThreadICMP();
	ICMP->device = ChosenDevice;
	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);

	RawPacket RP;
	stringstream stream;
	canSend = true;//���ƽ��պ��ٷ���
	int startPort = 8880;
	int endPort = 8890;
	cout << "ɨ�迪ʼ�˿ڣ�";
	cin >> startPort;
	cout << "ɨ������˿ڣ�";
	cin >> endPort;
	sendPort = startPort;
	time_t startTime = time(0), endTime;
	while (true)
	{
		endTime = time(0);
		//��������δ�յ��˿ڲ��ɴ�ж�Ϊ����
		if (endTime - startTime > 3)
		{
			cout << sendPort << "is open" << endl << endl;
			sendPort++;
			canSend = true;
		}
		if (sendPort > endPort)
		{
			//TerminateThread(hThread_icmp);
			CloseHandle(hThread_icmp);
			break;			
		}
		if (canSend)
		{
			startTime = time(0);
			stream << sendPort;
			stream >> DestinationPort;
			stream.clear();
			strcpy_s(udpScanData->DestinationPort, DestinationPort);
			cout << DestinationPort << endl;
			//�෢�ͼ���
			RP.CreatePacket(di.PhysicalAddress, desMAC, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
			canSend = false;
		}
	}
	//CloseHandle(hThread_icmp);

	cout <<"�˿�ɨ������"<< endl;
	map<int, int>::iterator tempMap;
	for (int i = startPort; i <= endPort; i++)
	{
		tempMap = portScan.find(i);
		if (tempMap == portScan.end())
		{
			cout << "�˿�" << i << "����" << endl;
		}
	}
	
	int choicedScanPort = 8888;
	cout << "ѡ��˿ڣ�";

	while (true)
	{
		cin >> choicedScanPort;
		if (choicedScanPort < startPort || choicedScanPort > endPort)
		{
			cout << "�ö˿ڲ���ɨ��˿ڷ�Χ�ڣ���������˿ڣ�";
			choicedScanPort = 0;
			continue;
		}

		if (portScan.find(choicedScanPort) != portScan.end())
		{
			cout << "�ö˿�δ���ţ�����ѡ��˿ڣ�";
		} else {
			break;
		}
	}
	stream.clear();
	stream << choicedScanPort;
	stream >> (udpScanData->DestinationPort);
	//stream.clear();
	//itoa(choicedScanPort, udpScanData->DestinationPort, 10);
	//to_string()
	//strcpy_s(udpScanData->DestinationPort, "8888");
	strcpy_s(udpScanData->DataString, "hello");
	//udpScanData->DataString = "hello";

	for (size_t i = 0; i < 10; i++)
	{
		//if (i % 4 ==0)
		//{
		//	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);
		//Sleep(200);
		//}
		//stream << i;
		//stream >> DestinationPort;
		//stream.clear();
		//strcpy_s(udpScanData->DestinationPort, DestinationPort);
		cout << udpScanData->DestinationPort << endl;

		HANDLE hThread_udpScan = CreateThread(NULL, 0, udpScan, udpScanData, 0, NULL);

		//ɨ��˿�ʱ��ֻ��Ҫ�ı�˿ڵ�ַ
			//if (strcmp(SourceMAC, "-1") == 0)
			//{
			//	if (strcmp(SourceIP, "-1") == 0)
			//	{
			//		//RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			//		RP.CreatePacket(di.PhysicalAddress, desMAC, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			//		RP.SendPacket(ChosenDevice);
			//		//return 0;
			//	}
			//	else
			//	{
			//		/*RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));*/
			//		RP.CreatePacket(di.PhysicalAddress, desMAC, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			//		RP.SendPacket(ChosenDevice);
			//	}
			//} 
			//else
			//{
			//	if (strcmp(SourceIP, "-1") == 0)
			//	{
			//		RP.CreatePacket(MACStringToBytes(SourceMAC), di.GatewayPhysicalAddress, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			//		RP.SendPacket(ChosenDevice);
			//	}
			//	else
			//	{
			//		RP.CreatePacket(MACStringToBytes(SourceMAC), di.GatewayPhysicalAddress, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			//		RP.SendPacket(ChosenDevice);
			//	}
			//}
		//Sleep(800);
	}
	cout << "����" << endl;
	system("pause");
}
//��MAC��ַ��ɨ�裬���̣߳�
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
		hostThreadScanTimes++;
		strcpy_s(sendIP, "");
	}
	return 0;
}