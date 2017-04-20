#include "NetworkStuff.h"
#include "RawPacket.h"
#include "icmp.h"



struct ThreadParamStruct
{
	pcap_if_t* ChosenDevice;

	char SourceIP[16];
	char SourcePort[6];
	char SourceMAC[19];

	char DestinationIP[16];
	char DestinationPort[6];
	unsigned char desMAC[6];

	char DataString[2048];

	DeviceInfo di;

};

static DWORD WINAPI udpScan(LPVOID lpParameter);

DWORD WINAPI udpScan(LPVOID lpParameter)
{
	ThreadParamStruct* scanData =  (ThreadParamStruct*)(lpParameter);
	//char SourceIP[16] = scanData->ChosenDevice;
	//char scanData->SourcePort[6];
	//char scanData->SourceMAC[19];

	//char DestinationIP[16];
	//char DestinationPort[6];
	//unsigned char scanData->desMAC[6];
	
	

	pcap_if_t* ChosenDevice = scanData->ChosenDevice;
	ThreadICMP *ICMP = new ThreadICMP();
	ICMP->device = ChosenDevice;
	ICMP->receivePort = atoi(scanData->DestinationPort);
	HANDLE hThread_icmp = CreateThread(NULL, 0, getICMP, ICMP, 0, NULL);

	char DataString[2048];
	memcpy(DataString, scanData->DataString, sizeof(scanData->DataString));
	DeviceInfo di = scanData->di;
	RawPacket RP;

	

	if (strcmp(scanData->SourceMAC, "-1") == 0)
	{
		if (strcmp(scanData->SourceIP, "-1") == 0)
		{
			//RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, di.IP, inet_addr(scanData->DestinationIP), atoi(scanData->SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.CreatePacket(di.PhysicalAddress, scanData->desMAC, di.IP, inet_addr(scanData->DestinationIP), atoi(scanData->SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
			//return 0;
		}
		else
		{
			/*RP.CreatePacket(di.PhysicalAddress, di.GatewayPhysicalAddress, inet_addr(scanData->SourceIP), inet_addr(scanData->DestinationIP), atoi(SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));*/
			RP.CreatePacket(di.PhysicalAddress, scanData->desMAC, inet_addr(scanData->SourceIP), inet_addr(scanData->DestinationIP), atoi(scanData->SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
		}
	}
	else
	{
		if (strcmp(scanData->SourceIP, "-1") == 0)
		{
			RP.CreatePacket(MACStringToBytes(scanData->SourceMAC), di.GatewayPhysicalAddress, di.IP, inet_addr(scanData->DestinationIP), atoi(scanData->SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
		}
		else
		{
			RP.CreatePacket(MACStringToBytes(scanData->SourceMAC), di.GatewayPhysicalAddress, inet_addr(scanData->SourceIP), inet_addr(scanData->DestinationIP), atoi(scanData->SourcePort), atoi(scanData->DestinationPort), (UCHAR*)DataString, strlen(DataString));
			RP.SendPacket(ChosenDevice);
		}
	}
	//getSimpleICMP(scanData->ChosenDevice);
	Sleep(50);
	return 0;
}