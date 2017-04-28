//#pragma once

//��Ĭ��windows.h�����winsock.h���������winsock2.h�ͻ��ͻ������ڰ���windows.hǰ��Ҫ����һ����,#define WIN32_LEAN_AND_MEAN ;ȥ��winsock.h
//Ҫô��#include <winsock2.h>����#include<windows.h>ǰ�����ֱ��ȥ��#include<windows.h>

//#include <winsock2.h>
//#pragma comment(lib, "WS2_32")    // ���ӵ�WS2_32.lib

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <iphlpapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <stdio.h>
using namespace std;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <windows.h> 

#include <map>
#include <string>
#include <string.h>
extern map <string, int> existHostMap;
extern map <string, int> hostScanStatus;

#define DEF_PACKET_SIZE 32
#define ECHO_REQUEST 8
#define ECHO_REPLY 0

struct IPHeader
{
	BYTE m_byVerHLen; //4λ�汾+4λ�ײ�����
	BYTE m_byTOS; //��������
	USHORT m_usTotalLen; //�ܳ���
	USHORT m_usID; //��ʶ
	USHORT m_usFlagFragOffset; //3λ��־+13λƬƫ��
	BYTE m_byTTL; //TTL
	BYTE m_byProtocol; //Э��
	USHORT m_usHChecksum; //�ײ������
	ULONG m_ulSrcIP; //ԴIP��ַ
	ULONG m_ulDestIP; //Ŀ��IP��ַ
};

struct ICMPHeader
{
	BYTE m_byType; //����
	BYTE m_byCode; //����
	USHORT m_usChecksum; //����� 
	USHORT m_usID; //��ʶ��
	USHORT m_usSeq; //���
	ULONG m_ulTimeStamp; //ʱ������Ǳ�׼ICMPͷ����
};

struct PingReply
{
	USHORT m_usSeq;
	DWORD m_dwRoundTripTime;
	DWORD m_dwBytes;
	DWORD m_dwTTL;
};

class CPing
{
public:
	CPing();
	~CPing();
	BOOL Ping(DWORD dwDestIP, PingReply *pPingReply = NULL, DWORD dwTimeout = 2000);
	BOOL Ping(char *szDestIP, PingReply *pPingReply = NULL, DWORD dwTimeout = 100);
private:
	BOOL PingCore(DWORD dwDestIP, PingReply *pPingReply, DWORD dwTimeout);
	USHORT CalCheckSum(USHORT *pBuffer, int nSize);
	ULONG GetTickCountCalibrate();
private:
	SOCKET m_sockRaw;
	WSAEVENT m_event;
	USHORT m_usCurrentProcID;
	char *m_szICMPData;
	BOOL m_bIsInitSucc;
private:
	static USHORT s_usPacketSeq;
};
