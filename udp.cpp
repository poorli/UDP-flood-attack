#include "udpScan.h"
#include "arp.h"
#include <ctime>

pcap_if_t* ChosenDevice;//选择的网卡
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

int main()
{
	ShowDeviceList();
	cout << "选择网关：" << endl;
	int chosen;
	cin >> chosen;
	int i = 1; char Error[PCAP_ERRBUF_SIZE];
	pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &ChosenDevice, Error);
	for (pcap_if_t* CurrentDevice = ChosenDevice; CurrentDevice != NULL; CurrentDevice = CurrentDevice->next)
	{
		if (i == chosen)
		{
			ChosenDevice = CurrentDevice;
			break;
		}
		i++;
	}
	//di为本地网卡信息
	DeviceInfo di;
	di = GetAdapterInfo(ChosenDevice);
	if (di.Exists == false)
	{
		cout << "Invalid Selection (Try another device)\n";
		return 0;
	}
	cout << "选择网卡为： " << ChosenDevice->name << endl;


	//desMAC[0] = 0x58;
	//desMAC[1] = 0x97;
	//desMAC[2] = 0xbd;
	//desMAC[3] = 0x5b;
	//desMAC[4] = 0x4b;
	//desMAC[5] = 0x80;

	//初始化发送数据
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
	//获取MAC地址存入全局变量ULONG MacAddr[2]中
	cout << "输入IP地址（如192.168.xxx.xxx）：";
	while (true)
	{
		cin >> DestinationIP;
		if (getMAC(SourceIP, DestinationIP) == FALSE)
		{
			cout << "获取MAC地址失败,请输入正确的IP：" << endl;
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

	//初始化udpScan()所需参数udpScanData
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
	

	//开启ICMP端口不可达接受线程
	ThreadICMP *ICMP = new ThreadICMP();
	ICMP->device = ChosenDevice;
	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);

	RawPacket RP;
	stringstream stream;
	canSend = true;//控制接收后再发送
	int startPort = 8880;
	int endPort = 8890;
	cout << "扫描开始端口：";
	cin >> startPort;
	cout << "扫描结束端口：";
	cin >> endPort;
	sendPort = startPort;
	time_t startTime = time(0), endTime;
	while (true)
	{
		endTime = time(0);
		//超过三秒未收到端口不可达，判断为开放
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
			//多发送几次
			RP.CreatePacket(di.PhysicalAddress, desMAC, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
			canSend = false;
		}
	}
	//CloseHandle(hThread_icmp);

	cout <<"端口扫描结果："<< endl;
	map<int, int>::iterator tempMap;
	for (int i = startPort; i <= endPort; i++)
	{
		tempMap = portScan.find(i);
		if (tempMap == portScan.end())
		{
			cout << "端口" << i << "开放" << endl;
		}
	}
	
	int choicedScanPort = 8888;
	cout << "选择端口：";

	while (true)
	{
		cin >> choicedScanPort;
		if (choicedScanPort < startPort || choicedScanPort > endPort)
		{
			cout << "该端口不在扫描端口范围内，重新输入端口：";
			choicedScanPort = 0;
			continue;
		}

		if (portScan.find(choicedScanPort) != portScan.end())
		{
			cout << "该端口未开放，重新选择端口：";
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

		//扫描端口时，只需要改变端口地址
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
	cout << "结束" << endl;
	system("pause");
}
//拿MAC地址，扫描，多线程？