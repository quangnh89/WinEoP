#pragma once
#include "EopUtilsType.h"
#include "crt.h"
#include "egghunt.h"
#include "EggTag.h"
#include "WinApiWrapper.h"
#include "KernelMode.h"

#ifdef __cplusplus
extern "C" {
#endif

	/************************************
	PoolAllocAndCopyViaAccelTable
	Allocate arbitrary kernel pool blocks using win32k!NtUserCreateAcceleratorTable
	Parameter: 
		__in LPENVIRONMENT env	
				A pointer to API Function table
		__in DWORD nNumberOfBytes
				The size of the region, in bytes. 
		LPVOID lpBuffer
				initialize buffer. lpBuffer may be  NULL.
	Return value:
	Address of allocated buffer
	*/
	HANDLE WINAPI PoolAllocAndCopyViaAccelTable(
		__in LPENVIRONMENT env, 
		__in DWORD nNumberOfBytes, 
		__inout_bcount(nNumberOfBytes - 0x12) LPVOID lpBuffer = NULL 
		);

	/************************************
	InjectCodeToAnotherProcess
	Parameter: 
		__in LPENVIRONMENT env
				A pointer to API Function table
		__in DWORD pid
				The identifier of the local process to be injected.
		__in LPVOID lpCode
				pointer to the buffer that contains code to be written in the address space of the specified process.
		__in SIZE_T dwCodeSize
				The number of bytes to be written to the specified process.
		__in_opt DWORD dwMilliseconds
				The time-out interval, in milliseconds. If dwMilliseconds is zero, the function tests the object's state and returns immediately. 
				If dwMilliseconds is INFINITE, the function's time-out interval never elapses.
		__in_opt LPVOID lpParameter
				A pointer to a variable to be passed to the thread function.
		__in_opt SIZE_T dwStackSize
				The initial size of the stack, in bytes. The system rounds this value to the nearest page. 
				If this parameter is 0 (zero), the new thread uses the default size for the executable.
	
	Return value:
		The return value is the calling thread's last-error code.
	*/
	DWORD WINAPI InjectCodeToAnotherProcess( 
		__in LPENVIRONMENT env, 
		__in DWORD pid, 
		__in LPVOID lpCode, 
		__in SIZE_T dwCodeSize, 
		__in_opt DWORD dwMilliseconds = 0, 
		__in_opt LPVOID lpParameter = NULL, 
		__in_opt SIZE_T dwStackSize = 0
		);

	/************************************
	LoadRemoteLibrary
	Maps the specified executable module into the address space of the specified process.
	
	Parameter: 
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in DWORD pid
			The identifier of the local process to be mapped.
		__in LPCSTR lpLibFileName
			The name of the executable module (either a .dll or .exe file). 
		__in_opt DWORD dwMilliseconds
			The time-out interval, in milliseconds. If dwMilliseconds is zero, the function tests the object's state and returns immediately. 
			If dwMilliseconds is INFINITE, the function's time-out interval never elapses.

	Return value:
		The return value is the calling thread's last-error code.
	*/
	DWORD WINAPI LoadRemoteLibrary(
		__in LPENVIRONMENT env, __in DWORD pid, 
		__in LPCSTR lpLibFileName, 
		__in_opt DWORD dwMilliseconds = 0
		);

	/************************************
	SetPrivilege
	The function enables or disables privilege in the specified process.
	Parameter: 
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in HANDLE hProcess
			Open handle to the specified process
		__in LPCSTR lpszPrivilege
			A pointer to a null-terminated string that specifies the name of the privilege, as defined in the Winnt.h header file. 
			For example, this parameter could specify the constant, SE_SECURITY_NAME, or its corresponding string, "SeSecurityPrivilege".
		__in BOOL bEnable
			Boolean that specifies whether to enable or disable the privilege.

	Return value:
		If the function succeeds, the return value is nonzero.
		If the function fails, the return value is zero. 
	*/
	BOOL WINAPI SetPrivilege(
		__in LPENVIRONMENT env,
		__in HANDLE hProcess, // process handle 
		__in LPCSTR lpszPrivilege, // name of privilege to enable/disable
		__in BOOL bEnable // enable or disable
		);

	/************************************
	GetParentPid
	
	Parameter: 
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in DWORD pid
			The identifier of the local process.

	Return value:
		Process ID of Parent process.
	*/
	DWORD GetParentPid( __in LPENVIRONMENT env, __in DWORD pid );

	/************************************
	Creates a new process and its primary thread. 
	The new process runs in the security context of the calling process.
	 Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
	   lpCommandLine 
			The command line to be executed. 
		wShowWindow
			Specifies how the window is to be shown. 
	Return Value
	      This function has no return value.
    */
	void SpawnNewProcess( __in LPENVIRONMENT env, __inout LPSTR lpCommandLine, __in WORD wShowWindow = SW_HIDE );

	/************************************
	Retrieves information about the current operating system.
	Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
	 Return Value
	     The return value is an error code: .
	 ENV_SUCCESS ( 0 ) : success
	 ENV_FAILURE (-1)  : failure
	*/
	int GetEnvironment( __inout LPENVIRONMENT env );

	/***********************************************************************
	Null-page preparation
	Parameters
	__in LPENVIRONMENT env
	A pointer to API Function table
	Return Value
	The return value is an error code:
	ENV_SUCCESS ( 0 ) : success
	ENV_FAILURE (-1)  : failure
	*/

	int NullPagePreparation( __inout LPENVIRONMENT env, __in LPVOID lpWndProc );

	/************************************
	LocateSharedInfo
		Retrieves gSharedInfo.
	
	Parameter: 
		__in LPENVIRONMENT env
			A pointer to API Function table
	*/
	PVOID LocateSharedInfo( __in LPENVIRONMENT env);

	/************************************
	GetFirstThreadHwnd
	Find HANDLE of the first attached window in current thread
	Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in PVOID pOwner
			owner of HWND
	Return Value
		HWND of the first attached window
	*/
	HWND GetFirstThreadHwnd( __in LPENVIRONMENT env, __in PVOID pOwner );

	/************************************
	GetAddressByHandle
	Convert HANDLE to address of win32k!_tagWND
	Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in HANDLE Handle
			HWND of window
	Return Value
		address of win32k!_tagWND
	*/
	PVOID GetAddressByHandle( __in LPENVIRONMENT env, __in HANDLE Handle );

	/************************************
	GetWin32kUserModeCallbackTable
	Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
	Return Value
		win32k!KernelCallbackTable
	*/
	PVOID GetWin32kUserModeCallbackTable( __in LPENVIRONMENT env );

	/************************************
	GetVersionString
	Query version string 
	Parameters
		__in LPENVIRONMENT env
			A pointer to API Function table
		__in DWORD nSize
			buffer size
		LPSTR lpVerStr
			a pointer to buffer
		Return value: 
			If the function succeeds, the return value is ERROR_SUCCESS.
			If the function fails, the return value is a nonzero error code defined in Winerror.h. 
	*/
	DWORD GetVersionString( __in LPENVIRONMENT env, __in DWORD nSize, __out_ecount(nSize) LPSTR lpVerStr );

	/************************************
	RtlInitLargeUnicodeString
	*/
	VOID RtlInitLargeUnicodeString( __out PLARGE_UNICODE_STRING plstr, __in LPCWSTR psz, __in UINT cchLimit);

	/* Get PTI, PEB, TEB,...
	Parameters
		__in LPENVIRONMENT env
		A pointer to API Function table
		*/
	void GetCurrentProcessEnvironment( __inout LPENVIRONMENT env);


	/************************************
	ClearHandleTableEntry
	Parameter: 
		__in LPBYTE CurrentProcess
			A pointer to _EPROCESS structure of current process. 
		__in HANDLE handle
			Opened handle
	*/
	void ClearHandleTableEntry( __in LPBYTE CurrentProcess, __in HANDLE handle );

	//************************************
	// Copy system process token to current process
	// Parameters
	//      lpCurrEprocess
	//			A pointer to _EPROCESS structure of current process. 
	// Return Value
	//      This function returns NT_SUCCESS if ok.
	NTSTATUS NTAPI StealSystemProcessToken( LPVOID * lpCurrEprocess = NULL );

	// anti-Virtual Machine
	// A way to know if the Windows machine I'm working on is virtual or physical?
	// 
	BOOL IsVm( __in LPENVIRONMENT env );

	//////////////////////////////////////////////////////////////////////////
	// Debug
	// these functions just for debugging and SHOULD NOT use in Release mode
	void PrintDebug( _In_z_ _Printf_format_string_ const char * _Format, ... );
	void OutputSystemError( __in_opt DWORD dwErr = 0 );
#ifdef __cplusplus
}
#endif
