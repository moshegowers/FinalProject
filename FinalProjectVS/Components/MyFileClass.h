#pragma once
#pragma once
#include <filesystem>
#include <map>
#include <experimental/filesystem>
using namespace std;
using namespace std::experimental::filesystem::v1;

class MyFileClass {
private:
	string _path;
	file_status _status;
	string _permissions;
	string filetype[9] = { "none", "regular", "directory", "symlink", "block", "character", "fifo", "socket", "unknown" };
public:
	MyFileClass(string path, file_status status, string fileperms)
		: _path(path), _status(status), _permissions(fileperms)
	{}
	string getPath() { return _path; }
	file_status getStatus() { return _status; }
	string getPermissions() { return _permissions; }
	string getFileType(int index) { return filetype[index]; }

};
