#include "NetworkStuff.h"
#include "RawPacket.h"

pcap_if_t* ChosenDevice;

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

	cout << "You chose: " << ChosenDevice->name << endl;

	char SourceIP[16];
	char SourcePort[6];
	char SourceMAC[19];

	char DestinationIP[16];
	char DestinationPort[6];

	char DataString[2048];
	//strcpy_s(SourceIP, "-1");
	//strcpy_s(SourceIP, "10.26.32.23");
	strcpy_s(SourceIP, "10.26.30.193");
	strcpy_s(SourcePort, "56921");
	strcpy_s(SourceMAC, "-1");
	//strcpy_s(DestinationIP, "123.206.80.223");
	strcpy_s(DestinationIP, "123.206.80.225");
	//strcpy_s(DestinationIP, "255.255.255.255");
	//strcpy_s(DestinationIP, "192.168.0.1");
	//strcpy_s(DestinationIP, "localhost");
	//strcpy_s(DestinationIP, "127.0.0.1");
	strcpy_s(DestinationPort, "8888");
	strcpy_s(DataString, "hello");
	unsigned char desMAC[6];
	//desMAC[0] = 0x70;
	//desMAC[1] = 0x7b;
	//desMAC[2] = 0xe8;
	//desMAC[3] = 0xc1;
	//desMAC[4] = 0xab;
	//desMAC[5] = 0x69;

	desMAC[0] = 0x58;
	desMAC[1] = 0x97;
	desMAC[2] = 0xbd;
	desMAC[3] = 0x5b;
	desMAC[4] = 0x4b;
	desMAC[5] = 0x80;
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

	RawPacket RP;
	for (size_t i = 0; i < 2; i++)
	{
		cout << i;
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
			
			//return 0;
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

		//if (strcmp(SourceIP, "-1") == 0)
		//{
		//	RP.CreatePacket(MACStringToBytes(SourceMAC), di.GatewayPhysicalAddress, di.IP, inet_addr(DestinationIP), atoi(SourcePort), atoi(DestinationPort), (UCHAR*)DataString, strlen(DataString));
		//	RP.SendPacket(ChosenDevice);
		//	//return 0;
		//}

		
	}
	
	system("pause");
}


//拿MAC地址，扫描，多线程？