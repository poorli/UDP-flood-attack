//copyright emmanuel herrera 2008

#ifndef _NETWORKSTUFF_H
#define _NETWORKSTUFF_H

#include "Includes.h"

struct  DeviceInfo
{
	bool Exists;
	UINT IP; //In case IP spoofing is not supported, use real IP
	UINT DefaultGateway;   // Where the packet is first sent
	unsigned char GatewayPhysicalAddress[6]; //MAC of destination (gateway)
	unsigned char PhysicalAddress[6]; //Source MAC in case MAC spoofing is not supported
};

// there is a better way to do this, but i forgot how  and this is how the RFC spec says to do it. 

unsigned short BytesTo16(unsigned char X, unsigned char Y)
{
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}
unsigned int BytesTo32(unsigned char W, unsigned char X, unsigned char Y, unsigned char Z)
{
	unsigned int Tmp = W;
	Tmp = Tmp << 8;
	Tmp = Tmp | X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	Tmp = Tmp << 8;
	Tmp = Tmp | Z;
	return Tmp;
}

void ShowDeviceList(void)
{
	char Error[PCAP_ERRBUF_SIZE];
	pcap_if_t* Devices; pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &Devices, Error);
	int i = 1;
	for (pcap_if_t* CurrentDevice = Devices; CurrentDevice != NULL; CurrentDevice = CurrentDevice->next)
	{
		cout << i << "description:" << CurrentDevice->description << endl;
		cout << inet_addr("10.26.30.193") << endl;
		i++;
	}
}

unsigned char* MACStringToBytes(LPSTR String)
{
	char* Tmp = new char[strlen(String)];
	memcpy((void*)Tmp, (void*)String, strlen(String));
	unsigned char* Returned = new unsigned char[6];
	for (int i = 0; i < 6; i++)
	{
		sscanf_s(Tmp, "%2X", &Returned[i]);
		memmove((void*)(Tmp), (void*)(Tmp + 3), 19 - i * 3);
	}
	return Returned;
}

DeviceInfo GetAdapterInfo(pcap_if_t* Device)
{
	DeviceInfo DevInfo;
	ZeroMemory(&DevInfo, sizeof(DevInfo));

	IP_ADAPTER_INFO* AdapterInfo = new IP_ADAPTER_INFO[48];
	ULONG AIS = sizeof(IP_ADAPTER_INFO)* 48;

	GetAdaptersInfo(AdapterInfo, &AIS);

	for (IP_ADAPTER_INFO* Current = AdapterInfo; Current != NULL; Current = Current->Next)
	{
		if (strstr(Device->name, Current->AdapterName) != 0)

		{
			cout << Device->addresses->addr->sa_data << endl;
			DevInfo.IP = BytesTo32(Device->addresses->addr->sa_data[2], Device->addresses->addr->sa_data[3],
				Device->addresses->addr->sa_data[4], Device->addresses->addr->sa_data[5]);

			DevInfo.DefaultGateway = inet_addr(Current->GatewayList.IpAddress.String);	// DevInfo.DefaultGateway

			DevInfo.IP = inet_addr(Current->IpAddressList.IpAddress.String); //DevInfo.IP
			
			memcpy((void*)DevInfo.PhysicalAddress, (void*)(Current->Address), 6); //DevInfo.PhysicalAddress
			ULONG MACSize = 6;

			//if (SendARP(DevInfo.DefaultGateway, NULL, (void*)DevInfo.GatewayPhysicalAddress, &MACSize) != NO_ERROR){
			//	cout << "SendARP Failed. No default gateway\n"; 
			//}

			//count();
			//count << DeviceInfo.GatewayPhysicalAddress;
			//DeviceInfo.GatewayPhysicalAddress = (void*)"70:7b:e8:c1:ab:69";
			//strcpy_s(DeviceInfo.GatewayPhysicalAddress, "70:7b:e8:c1:ab:69");
			//DeviceInfo.GatewayPhysicalAddress = 123.206.80.223;
			//DeviceInfo.GatewayPhysicalAddress[0] = 0x70;
			//DeviceInfo.GatewayPhysicalAddress[1] = 0x7b;
			//DeviceInfo.GatewayPhysicalAddress[2] = 0xe8;
			//DeviceInfo.GatewayPhysicalAddress[3] = 0xc1;
			//DeviceInfo.GatewayPhysicalAddress[4] = 0xab;
			//DeviceInfo.GatewayPhysicalAddress[5] = 0x69;
			//DeviceInfo.GatewayPhysicalAddress = 
			//DeviceInfo.GatewayPhysicalAddress = inet_addr("")
			DevInfo.Exists = true;
			return DevInfo;
		}
	}
	DevInfo.Exists = false;
	return DevInfo;
}
#endif