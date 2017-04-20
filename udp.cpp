//#include "NetworkStuff.h"
//#include "RawPacket.h"
//#include "icmp.h"

#include "udpScan.h"

#include <ctime>



pcap_if_t* ChosenDevice;
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
	cout << "Enter the number of your device (example: 2)" << endl;
	
	int chosen;
	//cin >> chosen;
	chosen = 1;
	//chosen = 1;

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

	DeviceInfo di;
	di = GetAdapterInfo(ChosenDevice);
	if (di.Exists == false)
	{
		cout << "Invalid Selection (Try another device)\n";
		return 0;
	}
	//getICMP(ChosenDevice);

	
	ThreadICMP *ICMP = new ThreadICMP();
	ICMP->device = ChosenDevice;


	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);

	cout << "You chose: " << ChosenDevice->name << endl;

	char SourceIP[16];
	char SourcePort[6];
	char SourceMAC[19];

	char DestinationIP[16];
	char DestinationPort[6];

	char DataString[2048];
	//strcpy_s(SourceIP, "-1");
	//strcpy_s(SourceIP, "10.26.32.23");
	//strcpy_s(SourceIP, "10.21.8.73");
	strcpy_s(SourceIP, "10.26.30.193");
	strcpy_s(SourcePort, "56921");
	strcpy_s(SourceMAC, "-1");
	strcpy_s(DestinationIP, "123.206.80.223");
	//strcpy_s(DestinationIP, "123.206.80.225");
	//strcpy_s(DestinationIP, "255.255.255.255");
	//strcpy_s(DestinationIP, "192.168.0.1");
	//strcpy_s(DestinationIP, "localhost");
	//strcpy_s(DestinationIP, "127.0.0.1");
	strcpy_s(DestinationPort, "8888");
	strcpy_s(DataString, "hello");
	unsigned char desMAC[6];
	desMAC[0] = 0x58;
	desMAC[1] = 0x97;
	desMAC[2] = 0xbd;
	desMAC[3] = 0x5b;
	desMAC[4] = 0x4b;
	desMAC[5] = 0x80;

	ThreadParamStruct *udpScanData = new ThreadParamStruct();
	udpScanData->ChosenDevice = ChosenDevice;

	strcpy_s(udpScanData->SourceMAC, SourceMAC);
	strcpy_s(udpScanData->SourceIP, SourceIP);
	strcpy_s(udpScanData->SourcePort, SourcePort);
	//char[] copy
	memcpy(udpScanData->desMAC, desMAC, sizeof(desMAC));
	strcpy_s(udpScanData->DestinationIP, DestinationIP);
	

	udpScanData->di = di;
	strcpy_s(udpScanData->DataString, "hello");
	//udpScanData->DataString = "hello";


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
	/*ChosenDevice->addresses->addr*/

	int startPort = 0;
	int endPort = 5;

	for (int i = startPort; i < endPort; i++)
	{
	//	//扫描端口时，只需要改变端口地址
	//	strcpy_s(DestinationPort, (char*)i);
		//HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);

	}
	stringstream stream;
	stringstream stream2;
	RawPacket RP;

	time_t startTime = time(0), endTime;
	canSend = true;
	sendPort = 8880;
	while (true)
	{
		endTime = time(0);
		if (endTime - startTime > 3)
		{
			cout << sendPort << "is open" << endl;
			sendPort++;
			canSend = true;
			
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
			if (strcmp(SourceMAC, "-1") == 0)
			{
				if (strcmp(SourceIP, "-1") == 0)
				{
					//RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
					RP.CreatePacket(di.PhysicalAddress, desMAC, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
					RP.SendPacket(ChosenDevice);
					//return 0;
				}
				else
				{
					/*RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));*/
					RP.CreatePacket(di.PhysicalAddress, desMAC, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
					RP.SendPacket(ChosenDevice);
				}
			} 
			else
			{
				if (strcmp(SourceIP, "-1") == 0)
				{
					RP.CreatePacket(MACStringToBytes(SourceMAC), di.GatewayPhysicalAddress, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
					RP.SendPacket(ChosenDevice);
				}
				else
				{
					RP.CreatePacket(MACStringToBytes(SourceMAC), di.GatewayPhysicalAddress, inet_addr(SourceIP), inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
					RP.SendPacket(ChosenDevice);
				}
			}
			canSend = false;
		}
		if (sendPort >= 8900)
		{
			break;
		}
	}
	for (size_t i = 0; i < 20; i++)
	{
		//if (i % 4 ==0)
		//{
		//	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);
			//Sleep(200);
		//}
		/*stream << i;
		stream >> DestinationPort;
		stream.clear();
		strcpy_s(udpScanData->DestinationPort, DestinationPort);
		cout << DestinationPort<<endl;*/

		//HANDLE hThread_udpScan = CreateThread(NULL, 0, udpScan, udpScanData, 0, NULL);

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
	//Sleep(2000);
	printf("hello");
	system("pause");
}


//拿MAC地址，扫描，多线程？