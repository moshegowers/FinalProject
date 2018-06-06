#pragma once
#ifndef MYSOCKET_H
#define MYSOCKET_H

#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
using namespace std;

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

class Socket
{
private:
	string _ipAddress;
	string _port;
	WSADATA _wsaData;
	int _iResult;
	addrinfo *_result;
	addrinfo _hints;
	SOCKET _socket;
public:
	Socket(){}
	Socket(string ip, string port);
	WSADATA GetWsaData();
	int Get_iResult();
	addrinfo * GetResult();
	SOCKET GetSocket();

	void CreateSocket(int family, int socktype, int protocol);
	int Connect(sockaddr * address, int length);
	int SendToServer(const char * message, int length);
	int ShutdownConnection();
	int ReciveFromServer(char * buff, int length);

	int Resolve();
	void FreeAddress();
	void Cleanup(bool closeSocket);
};

#endif
