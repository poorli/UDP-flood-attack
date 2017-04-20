#define  WIN32

#include "pcap.h"
#include <map>

#include <iostream>
using namespace std;
bool canSend;

int sendPort;
/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

map <int, int> portScan;

struct ThreadICMP
{
	pcap_if_t *device;
	int receivePort;
};

static DWORD WINAPI getICMP(LPVOID lpParameter);

DWORD WINAPI getICMP(LPVOID lpParameter)
{
	ThreadICMP* Device = (ThreadICMP*)lpParameter;
	pcap_if_t *device = Device->device;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	//char packet_filter[] = "icmp and udp";
	////char packet_filter[] = "ip src host 123.206.80.255";
	char packet_filter[] = "icmp[icmptype] == icmp-unreach";

	//char packet_filter[] = "udp";
	//char packet_filter[] = "host 123.206.80.223";

	struct bpf_program fcode;

	/* Retrieve the device list */


	/* Print the list */


	/* Jump to the selected adapter */
	//for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the adapter */
	//for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	/*lpParameter->device*/
	if ((adhandle = pcap_open(device->name,  // name of the device
		65536,     // portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL,      // remote authentication
		errbuf     // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}

	if (device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}

	//printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	//pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}


void getSimpleICMP(pcap_if_t *device);

void getSimpleICMP(pcap_if_t *device)
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;

	//char packet_filter[] = "icmp and udp";
	////char packet_filter[] = "ip src host 123.206.80.255";
	char packet_filter[] = "icmp[icmptype] == icmp-unreach";


	/* Open the adapter */
	/*lpParameter->device*/
	if ((adhandle = pcap_open(device->name,  // name of the device
		65536,     // portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL,      // remote authentication
		errbuf     // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}

	if (device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		//pcap_freealldevs(alldevs);
		//return -1;
	}


	/* At this point, we don't need any more the device list. Free it */
	//pcap_freealldevs(alldevs);

	/* start the capture */
	printf("start loop");
	pcap_loop(adhandle, 0, packet_handler, NULL);
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm ltime;
	char timestr[16];

	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;
	/*
	* Unused variable
	*/
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	//cout << endl << pkt_data << endl;
	/* print timestamp and length of the packet */
	printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);
	cout << endl;


	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		14); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	//ip_len = 20;
	//用于接受目的端口
	ip_len = 2 * ip_len + 8;
	uh = (udp_header *)((u_char*)ih + ip_len);
	//uh = (udp_header *)ih + ip_len;

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	cout << ih->daddr.byte1 << endl;
	cout << uh->sport << endl;
	cout << uh->dport << endl;
	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	//PORT_SCAN[1] = 1;
	portScan[dport] = 1;
	//
	if (dport == sendPort)
	{
		canSend = true;
		sendPort++;
	}
	//testMap
	//testMap.insert(map<int, int>::value_type(int 1, int 1));
	//port_scan.insert(map<int, int>::value_type(1, 1));
	//PORT_SCAN.insert(map<int, int>::value_type(1, 1));
}