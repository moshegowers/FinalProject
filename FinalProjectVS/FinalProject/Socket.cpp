#include "Socket.h"
using namespace std;

Socket::Socket(string ip, string port):
	_ipAddress(ip), _port(port)
{
	// Initialize Winsock
	_result = NULL;
	_iResult = WSAStartup(MAKEWORD(2, 2), &_wsaData);
	ZeroMemory(&_hints, sizeof(_hints));
	_hints.ai_family = AF_UNSPEC;
	_hints.ai_socktype = SOCK_STREAM;
	_hints.ai_protocol = IPPROTO_TCP;
	_socket = INVALID_SOCKET;
}

WSADATA Socket::GetWsaData()
{
	return _wsaData;
}

int Socket::Get_iResult()
{
	return _iResult;
}

addrinfo * Socket::GetResult()
{
	return _result;
}

SOCKET Socket::GetSocket()
{
	return _socket;
}

void Socket::CreateSocket(int family, int socktype, int protocol)
{
	_socket = socket(family, socktype, protocol);;
}

int Socket::Connect(sockaddr * address, int length)
{
	return connect(_socket, address, length);
}

int Socket::SendToServer(const char * message, int length)
{
	return send(_socket, message, length, 0);
}

int Socket::ShutdownConnection()
{
	return shutdown(_socket, SD_SEND);
}

int Socket::ReciveFromServer(char * buff, int length)
{
	return recv(_socket, buff, length, 0);
}

int Socket::Resolve()
{
	return getaddrinfo(_ipAddress.c_str(), _port.c_str(), &_hints, &_result);
}

void Socket::FreeAddress()
{
	freeaddrinfo(_result);
}

void Socket::Cleanup(bool closeSocket)
{
	if (closeSocket)
	{
		closesocket(_socket);
		_socket = INVALID_SOCKET;
	}
	WSACleanup();
}
