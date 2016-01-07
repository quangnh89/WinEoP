#pragma once
#include "Utils/EopUtils.h"

typedef BOOL (__cdecl * FP_EXPLOIT)( __in LPENVIRONMENT lpEnv, __in DWORD dwPid, __inout_opt LPSTR lpCommandLine, __in WORD wShowWindow );
typedef void (__cdecl * GETROOT)( __inout ENVIRONMENT *lpEnv);
#ifdef __cplusplus
extern "C" {
#endif
	void GetRoot( __inout ENVIRONMENT *lpEnv);
#ifdef __cplusplus
}
#endif


	/************************************
	Exploit Elevation of privilege Vulnerability
	Parameter: 
	    __in DWORD dwPid : Process ID to get elevation
	If dwPid == Current process, this function will spawn new process
	     lpCommandLine :  The command line to be executed. 
	 		wShowWindow   : Specifies how the window is to be shown. 
	Return Values
		If the function succeeds, the return value is a nonzero value.
	  If the function fails, the return value is zero. 

	  BOOL Exploit( __in LPENVIRONMENT lpEnv, __in DWORD dwPid, __inout_opt LPSTR lpCommandLine = NULL, __in WORD wShowWindow = SW_HIDE );
    */
	

namespace CVE_2015_1701
{
	BOOL Exploit( __in LPENVIRONMENT lpEnv, __in DWORD dwPid, __inout_opt LPSTR lpCommandLine = NULL, __in WORD wShowWindow = SW_HIDE );
}
