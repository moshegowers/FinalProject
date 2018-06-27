//#define HAVE_REMOTE
#pragma warning
#include "arpspoof.h"
#include "SniffTraffic.h"
#include "Components.h"
#include "DnsPoison.h"
#include <iostream>
#include <thread>
using namespace std;
//#include <tins/tins.h>


int main(int argc, char **argv)
{
	//SpoofVictim("192.168.43.161");



	//SniffTraffic st;
	//st.SniffByFilter();
	/*char filter[8] = "";
	SniffTraffic st(filter, 1000);
	st.Capture();*/
	DnsPoison* t = new DnsPoison(NULL, 100);
	t->Capture();
	system("pause");

}
