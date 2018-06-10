//#define HAVE_REMOTE
#pragma warning
#include "arpspoof.h"
#include "SniffTraffic.h"



int main(int argc, char **argv)
{
	Arpspoof a;
	bool retflag;
	int retval = a.SendArpReplayForSpoofing(retflag);
	if (retflag) return retval;

	SniffTraffic st;
	st.SniffByFilter();

	return 0;
}
