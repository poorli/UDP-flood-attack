#ifndef _INCLUDES_H
#define _INCLUDES_H
//#define WIN32


#include <winsock2.h> // htons() htonl() and other helper functions
#pragma comment (lib,"WS2_32.lib") 
#include <windows.h> 
#include <string>
#include <sstream>
#include <Iphlpapi.h>// Used to find information about the device such as default gateway and hardware addresses
#pragma comment (lib,"Iphlpapi.lib") 
//#include <Pcap/pcap.h> // WinPCap
#include <pcap/pcap.h>
#include <remote-ext.h>
#pragma comment (lib,"wpcap.lib") // Link to
#include <iostream> //sprintf()
using namespace std;

#endif