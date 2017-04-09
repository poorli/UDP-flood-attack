//Copyright Emmanuel Herrera 2008
#include "Includes.h"

class RawPacket
{
public:
	unsigned char* FinalPacket;
	void CreatePacket(unsigned char* SourceMAC,
		unsigned char* DestinationMAC,
		unsigned int   SourceIP,
		unsigned int   DestinationIP,
		unsigned short SourcePort,
		unsigned short DestinationPort,
		unsigned char* UserData,
		unsigned int   DataLen);
	unsigned int UserDataLen;

	void SendPacket(pcap_if_t* Device);
private:
	unsigned short CalculateUDPChecksum(unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol);
	unsigned short CalculateIPChecksum(UINT TotalLen, UINT ID, UINT SourceIP, UINT DestIP);
};
void RawPacket::CreatePacket
(unsigned char* SourceMAC,
unsigned char* DestinationMAC,
unsigned int   SourceIP,
unsigned int   DestIP,
unsigned short SourcePort,
unsigned short DestinationPort,
unsigned char* UserData,
unsigned int   UserDataLen)
{
	RawPacket::UserDataLen = UserDataLen;
	FinalPacket = new unsigned char[UserDataLen + 42]; // Reserve enough memory for the length of the data plus 42 bytes of headers 
	USHORT TotalLen = UserDataLen + 20 + 8; // IP Header uses length of data plus length of ip header (usually 20 bytes) plus lenght of udp header (usually 8)


	//Beginning of Ethernet II Header
	memcpy((void*)FinalPacket, (void*)DestinationMAC, 6);
	memcpy((void*)(FinalPacket + 6), (void*)SourceMAC, 6);
	USHORT TmpType = 8;
	//USHORT TmpType = 0x8864;
	memcpy((void*)(FinalPacket + 12), (void*)&TmpType, 2); //The type of protocol used. (USHORT) Type 0x08 is UDP. You can change this for other protocols (e.g. TCP)


	// Beginning of IP Header
	memcpy((void*)(FinalPacket + 14), (void*)"\x45", 1); //The Version (4) in the first 3 bits  and the header length on the last 5. (Im not sure, if someone could correct me plz do)
	//If you wanna do any IPv6 stuff, you will need to change this. but i still don't know how to do ipv6 myself =s 
	memcpy((void*)(FinalPacket + 15), (void*)"\x00", 1); //Differntiated services field. Usually 0 
	TmpType = htons(TotalLen);
	memcpy((void*)(FinalPacket + 16), (void*)&TmpType, 2);
	TmpType = htons(0x1337);
	memcpy((void*)(FinalPacket + 18), (void*)&TmpType, 2);// Identification. Usually not needed to be anything specific, esp in udp. 2 bytes (Here it is 0x1337
	memcpy((void*)(FinalPacket + 20), (void*)"\x00", 1); // Flags. These are not usually used in UDP either, more used in TCP for fragmentation and syn acks i think 
	memcpy((void*)(FinalPacket + 21), (void*)"\x00", 1); // Offset
	memcpy((void*)(FinalPacket + 22), (void*)"\x80", 1); // Time to live. Determines the amount of time the packet can spend trying to get to the other computer. (I see 128 used often for this)
	memcpy((void*)(FinalPacket + 23), (void*)"\x11", 1);// Protocol. UDP is 0x11 (17) TCP is 6 ICMP is 1 etc
	memcpy((void*)(FinalPacket + 24), (void*)"\x00\x00", 2); //checksum 
	memcpy((void*)(FinalPacket + 26), (void*)&SourceIP, 4); //inet_addr does htonl() for us
	memcpy((void*)(FinalPacket + 30), (void*)&DestIP, 4);
	//Beginning of UDP Header
	TmpType = htons(SourcePort);
	memcpy((void*)(FinalPacket + 34), (void*)&TmpType, 2);
	TmpType = htons(DestinationPort);
	memcpy((void*)(FinalPacket + 36), (void*)&TmpType, 2);
	USHORT UDPTotalLen = htons(UserDataLen + 8); // UDP Length does not include length of IP header
	memcpy((void*)(FinalPacket + 38), (void*)&UDPTotalLen, 2);
	//memcpy((void*)(FinalPacket+40),(void*)&TmpType,2); //checksum
	memcpy((void*)(FinalPacket + 42), (void*)UserData, UserDataLen);

	unsigned short UDPChecksum = CalculateUDPChecksum(UserData, UserDataLen, SourceIP, DestIP, htons(SourcePort), htons(DestinationPort), 0x11);
	memcpy((void*)(FinalPacket + 40), (void*)&UDPChecksum, 2);

	unsigned short IPChecksum = htons(CalculateIPChecksum(TotalLen, 0x1337, SourceIP, DestIP));
	memcpy((void*)(FinalPacket + 24), (void*)&IPChecksum, 2);

	return;

}
unsigned short RawPacket::CalculateIPChecksum(UINT TotalLen, UINT ID, UINT SourceIP, UINT DestIP)
{
	unsigned short CheckSum = 0;
	for (int i = 14; i<34; i += 2)
	{
		unsigned short Tmp = BytesTo16(FinalPacket[i], FinalPacket[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum;
	return CheckSum;
}
unsigned short RawPacket::CalculateUDPChecksum(unsigned char* UserData, int UserDataLen, UINT SourceIP, UINT DestIP, USHORT SourcePort, USHORT DestinationPort, UCHAR Protocol)
{
	unsigned short CheckSum = 0;
	unsigned short PseudoLength = UserDataLen + 8 + 9; //Length of PseudoHeader = Data Length + 8 bytes UDP header (2Bytes Length,2 Bytes Dst Port, 2 Bytes Src Port, 2 Bytes Checksum)
	//+ Two 4 byte IP's + 1 byte protocol
	PseudoLength += PseudoLength % 2; //If bytes are not an even number, add an extra.
	unsigned short Length = UserDataLen + 8; // This is just UDP + Data length. needed for actual data in udp header

	unsigned char* PseudoHeader = new unsigned char[PseudoLength];
	for (int i = 0; i < PseudoLength; i++){ PseudoHeader[i] = 0x00; }

	PseudoHeader[0] = 0x11;

	memcpy((void*)(PseudoHeader + 1), (void*)(FinalPacket + 26), 8); // Source and Dest IP

	Length = htons(Length);
	memcpy((void*)(PseudoHeader + 9), (void*)&Length, 2);
	memcpy((void*)(PseudoHeader + 11), (void*)&Length, 2);

	memcpy((void*)(PseudoHeader + 13), (void*)(FinalPacket + 34), 2);
	memcpy((void*)(PseudoHeader + 15), (void*)(FinalPacket + 36), 2);

	memcpy((void*)(PseudoHeader + 17), (void*)UserData, UserDataLen);


	for (int i = 0; i < PseudoLength; i += 2)
	{
		unsigned short Tmp = BytesTo16(PseudoHeader[i], PseudoHeader[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference){ CheckSum += 1; }
	}
	CheckSum = ~CheckSum; //One's complement
	return CheckSum;
}
void RawPacket::SendPacket(pcap_if_t* Device)
{
	char Error[256];
	pcap_t* t;
	t = pcap_open(Device->name, 65535, PCAP_OPENFLAG_DATATX_UDP, 1, NULL, Error);//FP for send
	/*pcap_sendpacket(t, FinalPacket, UserDataLen + 42);*/
	if (pcap_sendpacket(t, FinalPacket, UserDataLen + 42) == 0)
	{
		cout << "send success\n";
	}
	else
	{
		cout << "send error\n";
	}

	pcap_close(t);


}
