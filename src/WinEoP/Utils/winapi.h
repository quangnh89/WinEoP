#pragma once
#include <tchar.h>
#include <WTypes.h>
#include <winternl.h>
#include <TlHelp32.h>

typedef PVOID PEPROCESS ;
typedef LONG  KPROFILE_SOURCE ;
typedef LONG  WORKERFACTORYINFOCLASS ;
typedef LONG  NTSTATUS ;
typedef PVOID	PHEAD;

#define MAKEINTATOMA(i) (LPSTR)((ULONG_PTR)((WORD)(i)))

#ifndef STATUS_FAIL_CHECK
#define STATUS_FAIL_CHECK ((NTSTATUS)0xC0000229L)
#endif // STATUS_FAIL_CHECK

#ifndef STATUS_NO_SUCH_PRIVILEGE
#define STATUS_NO_SUCH_PRIVILEGE ((NTSTATUS)0xC0000060L)
#endif // STATUS_NO_SUCH_PRIVILEGE

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif // STATUS_INFO_LENGTH_MISMATCH

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) 
#endif // STATUS_SUCCESS

#define SystemModuleInformation     (11)
//////////////////////////////////////////////////////////////////////////
// Menu notification message 
#define MN_SETHMENU					0x01E0
#define MN_GETHMENU					0x01E1
#define MN_SIZEWINDOW				0x01E2	// xxxSetWindowPos
#define MN_OPENHIERARCHY			0x01E3	// xxxMNOpenHierarchy
#define MN_CLOSEHIERARCHY			0x01E4	// xxxMNCloseHierarchy
#define MN_SELECTITEM				0x01E5	// xxxMNSelectItem
#define MN_CANCELMENUS				0x01E6	// xxxMNCancel
#define MN_SELECTFIRSTVALIDITEM		0x01E7	// MNFindNextValidItem(); xxxSendMessage(MN_SELECTITEM)
#define MN_GETPPOPUPMENU			0x01EA  // Get current Item
#define MN_FINDMENUWINDOWFROMPOINT  0x01EB	// xxxMNFindWindowFromPoint
#define MN_SHOWPOPUPWINDOW          0x01EC	// xxxShowWindow
#define MN_BUTTONDOWN               0x01ED	// xxxMNButtonDown
#define MN_MOUSEMOVE                0x01EE	// xxxMNMouseMove
#define MN_BUTTONUP                 0x01EF	// xxxMNButtonUp
#define MN_SETTIMERTOOPENHIERARCHY  0x01F0	// MNSetTimerToOpenHierarchy
#define MN_DBLCLK                   0x01F1	// xxxMNDoubleClick
#define MN_ACTIVEMENU               0x01F2	// xxxActivateThisWindow
#define MN_DODRAGDROP               0x01F3  // xxxMNCloseHierarchy
#define MN_ENDMENU                  0x01F4	// xxxUnlockAndEndMenuState

//////////////////////////////////////////////////////////////////////////
/*
dt win32k!tagSHAREDINFO
+0x000 psi              : Ptr64 tagSERVERINFO
+0x008 aheList          : Ptr64 _HANDLEENTRY
*/
#define TYPE_WINDOW  (1)
#define HMUNIQSHIFT (16)

typedef struct _HANDLEENTRY {
	PHEAD   phead;  // Pointer to the Object.
	PVOID   pOwner; // PTI or PPI
	BYTE    bType;  // Object handle type
	BYTE    bFlags; // Flags
	WORD    wUniq;  // Access count.
} HANDLEENTRY, *PHANDLEENTRY;

typedef struct _SERVERINFO {
	DWORD           dwSRVIFlags;
	ULONG_PTR       cHandleEntries;
	// incomplete
} SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
	PSERVERINFO		psi;
	PHANDLEENTRY	aheList;
	ULONG			HeEntrySize; // not present in WinXP, Win 2k3
	// incomplete
} SHAREDINFO, *PSHAREDINFO;

typedef struct _EX_FAST_REF 
{
	union 
	{
		PVOID Object;
#if defined _M_IX86
		ULONG RefCnt: 3;
#elif (defined _M_AMD64) || (defined _WIN64)
		ULONG RefCnt: 4;
#endif
		ULONG Value;
	} u;
}EX_FAST_REF, *PEX_FAST_REF;

#pragma pack(push, 1)
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	ULONG Reserved[2];
#if defined _WIN64 || defined _M_X64
	ULONG Reserved2[3];
#endif
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	char   ImageName[256];    
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[ANYSIZE_ARRAY];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;


#pragma pack(pop)


//////////////////////////////////////////////////////////////////////////

// Function

typedef NTSTATUS (NTAPI *ZWQUERYSYSTEMINFORMATION)(
	LONG /*SYSTEM_INFORMATION_CLASS*/ SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength 
	);

typedef NTSTATUS (NTAPI *ZWALLOCATEVIRTUALMEMORY)(
	HANDLE   ProcessHandle,
	PVOID  * BaseAddress,
	ULONG    ZeroBits,
	PSIZE_T  RegionSize,
	ULONG    AllocationType,
	ULONG    Protect 
	); 

typedef NTSTATUS(NTAPI *PSLOOKUPPROCESSBYPROCESSID)(
	HANDLE ProcessId,
	LPBYTE *Process 
	);

typedef NTSTATUS (NTAPI *NTCREATEWORKERFACTORY)(
	_Out_    PHANDLE WorkerFactoryHandleReturn,
	_In_     ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_     HANDLE CompletionPortHandle,
	_In_     HANDLE WorkerProcessHandle,
	_In_     PVOID StartRoutine,
	_In_opt_ PVOID StartParameter,
	_In_opt_ ULONG MaxThreadCount,
	_In_opt_ SIZE_T StackReserve,
	_In_opt_ SIZE_T StackCommit
	);

typedef NTSTATUS (NTAPI *NTSETINFORMATIONWORKERFACTORY)(
	_In_ HANDLE WorkerFactoryHandle,
	_In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	_In_ PVOID WorkerFactoryInformation,
	_In_ ULONG WorkerFactoryInformationLength
	);

typedef NTSTATUS (NTAPI *NTQUERYINFORMATIONWORKERFACTORY)(
	_In_      HANDLE WorkerFactoryHandle,
	_In_      WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	_Out_     PVOID WorkerFactoryInformation,
	_In_      ULONG WorkerFactoryInformationLength,
	_Out_opt_ PULONG ReturnLength
	); 

typedef NTSTATUS (NTAPI *NTQUERYEAFILE)(
	_In_     HANDLE FileHandle,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID Buffer,
	_In_     ULONG Length,
	_In_     BOOLEAN ReturnSingleEntry,
	_In_     PVOID EaList,
	_In_     ULONG EaListLength,
	_In_opt_ PULONG EaIndex OPTIONAL,
	_In_     BOOLEAN RestartScan
	);

typedef NTSTATUS (NTAPI *NTQUERYINTERVALPROFILE)(
	_In_  KPROFILE_SOURCE ProfileSource,
	_Out_ PULONG          Interval
	);

//////////////////////////////////////////////////////////////////////////
// User mode
typedef HMODULE (WINAPI *LOADLIBRARYA)( __in LPCSTR lpLibFileName );
typedef HMODULE (WINAPI *LOADLIBRARYW)( __in LPCWSTR lpLibFileName );
typedef FARPROC (WINAPI *GETPROCADDRESS)(
	__in HMODULE hModule, 
	__in LPCSTR lpProcName 
	);

typedef HMODULE (WINAPI *LOADLIBRARYEXA)(
	__in LPCSTR lpLibFileName,
	__reserved HANDLE hFile,
	__in DWORD dwFlags 
	);
typedef BOOL (WINAPI *VIRTUALPROTECT)(
	__in LPVOID lpAddress,
	__in SIZE_T dwSize,
	__in DWORD flNewProtect,
	__out PDWORD lpflOldProtect
	);

typedef BOOL (WINAPI *ISWOW64PROCESS) (HANDLE, PBOOL);

typedef HANDLE (WINAPI *CREATETOOLHELP32SNAPSHOT)( __in DWORD dwFlags, __in DWORD th32ProcessID );
typedef BOOL (WINAPI *PROCESS32FIRSTW)( __in          HANDLE hSnapshot, __inout      LPPROCESSENTRY32W lppe );
typedef BOOL (WINAPI *PROCESS32NEXTW)(
								  __in          HANDLE hSnapshot,
								  __out         LPPROCESSENTRY32W lppe
								  );
typedef BOOL (WINAPI *CLOSEHANDLE)(
								__in          HANDLE hObject
								);

typedef DWORD (WINAPI *GETCURRENTPROCESSID)(void);
typedef DWORD (WINAPI *EXPANDENVIRONMENTSTRINGSA)(
	__in          LPCSTR lpSrc,
	__out         LPSTR lpDst,
	__in          DWORD nSize
	);

typedef BOOL (WINAPI *CREATEPROCESSA)(
								  __in          LPCSTR lpApplicationName,
								  __inout       LPSTR lpCommandLine,
								  __in          LPSECURITY_ATTRIBUTES lpProcessAttributes,
								  __in          LPSECURITY_ATTRIBUTES lpThreadAttributes,
								  __in          BOOL bInheritHandles,
								  __in          DWORD dwCreationFlags,
								  __in          LPVOID lpEnvironment,
								  __in          LPCSTR lpCurrentDirectory,
								  __in          LPSTARTUPINFOA lpStartupInfo,
								  __out         LPPROCESS_INFORMATION lpProcessInformation
								  );

typedef BOOL (WINAPI *GETVERSIONEXA)(
								 __inout      LPOSVERSIONINFOA lpVersionInfo
								 );

typedef HANDLE (WINAPI *GETCURRENTPROCESS)(void);
typedef HGLOBAL (WINAPI *GLOBALALLOC)(
								   __in          UINT uFlags,
								   __in          SIZE_T dwBytes
								   );

typedef HMODULE (WINAPI *GETMODULEHANDLEA)(
									   __in LPCSTR lpModuleName
									   );
typedef HGLOBAL (WINAPI *GLOBALFREE)(
								  __in          HGLOBAL hMem
								  );

typedef BOOL (WINAPI *FREELIBRARY)(
						__in          HMODULE hModule
						);

typedef LONG (WINAPI *REGOPENKEYEXA)(
								 __in          HKEY hKey,
								 __in          LPCSTR lpSubKey,
								 DWORD ulOptions,
								 __in          REGSAM samDesired,
								 __out         PHKEY phkResult
								 );

typedef LONG (WINAPI *REGQUERYVALUEEXA)(
									__in          HKEY hKey,
									__in          LPCSTR lpValueName,
									LPDWORD lpReserved,
									__out         LPDWORD lpType,
									__out         LPBYTE lpData,
									__inout      LPDWORD lpcbData
									);

typedef LONG (WINAPI *REGCLOSEKEY)(
								__in          HKEY hKey
								);

typedef void (WINAPI *SETLASTERROR)(   DWORD dwErrCode); 

typedef SIZE_T (WINAPI *VIRTUALQUERY)(
								   __in          LPCVOID lpAddress,
								   __out         PMEMORY_BASIC_INFORMATION lpBuffer,
								   __in          SIZE_T dwLength
								   );

typedef BOOL (WINAPI *ISBADREADPTR)(
								 __in          const VOID* lp,
								 __in          UINT_PTR ucb
								 );

typedef DWORD (WINAPI *GETLASTERROR)(void);

typedef ATOM (WINAPI *REGISTERCLASSA)( __in CONST WNDCLASSA *lpWndClass);
typedef HWND (WINAPI * CREATEWINDOWEXA)(
				__in DWORD dwExStyle,
				__in_opt LPCSTR lpClassName,
				__in_opt LPCSTR lpWindowName,
				__in DWORD dwStyle,
				__in int X,
				__in int Y,
				__in int nWidth,
				__in int nHeight,
				__in_opt HWND hWndParent,
				__in_opt HMENU hMenu,
				__in_opt HINSTANCE hInstance,
				__in_opt LPVOID lpParam);

typedef BOOL (WINAPI *UNREGISTERCLASSA)(
				 __in LPCSTR lpClassName,
				 __in_opt HINSTANCE hInstance);

typedef BOOL (WINAPI *DESTROYWINDOW)( __in HWND hWnd);
typedef LPVOID (WINAPI *VIRTUALALLOC)(
						   __in          LPVOID lpAddress,
						   __in          SIZE_T dwSize,
						   __in          DWORD flAllocationType,
						   __in          DWORD flProtect
						   );

typedef BOOL (WINAPI *VIRTUALFREE)(
								__in          LPVOID lpAddress,
								__in          SIZE_T dwSize,
								__in          DWORD dwFreeType
								);

typedef HHOOK (WINAPI *SETWINDOWSHOOKEXA)(          int idHook,
							   HOOKPROC lpfn,
							   HINSTANCE hMod,
							   DWORD dwThreadId
							   );

typedef DWORD (WINAPI *GETCURRENTTHREADID)( VOID );

typedef BOOL (WINAPI *SETFOREGROUNDWINDOW)( HWND hWnd );
typedef BOOL( WINAPI *TRACKPOPUPMENU)(          HMENU hMenu,
							UINT uFlags,
							int x,
							int y,
							int nReserved,
							HWND hWnd,
							HWND prcRect
							);

typedef BOOL (WINAPI *POSTMESSAGEA)( __in_opt HWND hWnd, __in UINT Msg, __in WPARAM wParam, __in LPARAM lParam);
typedef BOOL (WINAPI *UNHOOKWINDOWSHOOK)( __in int nCode, __in HOOKPROC pfnFilterProc);
typedef BOOL (WINAPI *DESTROYMENU)( __in HMENU hMenu);
typedef LONG (WINAPI *SETWINDOWLONGA)( __in HWND hWnd, __in int nIndex, __in LONG_PTR dwNewLong);
typedef LRESULT (WINAPI *CALLNEXTHOOKEX)( __in_opt HHOOK hhk, __in int nCode, __in WPARAM wParam, __in LPARAM lParam);
typedef HMENU (WINAPI *CREATEPOPUPMENU)(VOID);
typedef BOOL (WINAPI *INSERTMENUITEMA)( __in HMENU hmenu, __in UINT item, __in BOOL fByPosition, __in LPCMENUITEMINFOA lpmi);
typedef LRESULT (WINAPI *CALLWINDOWPROCA)( __in FARPROC lpPrevWndFunc, __in HWND hWnd, __in UINT Msg, __in WPARAM wParam, __in LPARAM lParam);
typedef BOOL (WINAPI *ENDMENU)(VOID);

typedef LRESULT (CALLBACK * DEFWINDOWPROCA)( __in HWND hWnd, __in UINT Msg, __in WPARAM wParam, __in LPARAM lParam);

typedef HICON (WINAPI *LOADICONA)( __in_opt HINSTANCE hInstance, __in LPCSTR lpIconName);
typedef ATOM (WINAPI *REGISTERCLASSEXA)( __in CONST WNDCLASSEXA *);

typedef LONG (WINAPI * INTERLOCKEDEXCHANGE) ( __inout LONG volatile *Target, __in    LONG Value );
typedef DWORD (WINAPI * SETCLASSLONGA)(
			  __in HWND hWnd,
			  __in int nIndex,
			  __in LONG dwNewLong);

typedef int ( WINAPI * ENUMPROPSEXA)(
			 __in HWND hWnd,
			 __in PROPENUMPROCEXA lpEnumFunc,
			 __in LPARAM lParam);

typedef HANDLE (WINAPI * REMOVEPROPA)( __in HWND hWnd, __in LPCSTR lpString);
typedef int (WINAPIV * WSPRINTFA)( __out LPSTR, __in __format_string LPCSTR, ...);

typedef BOOL (WINAPI * SETPROPA)( __in HWND hWnd, __in LPCSTR lpString, __in_opt HANDLE hData);
typedef BOOL (WINAPI * DEVICEIOCONTROL)(
										__in        HANDLE hDevice,
										__in        DWORD dwIoControlCode,
										__in_bcount_opt(nInBufferSize) LPVOID lpInBuffer,
										__in        DWORD nInBufferSize,
										__out_bcount_part_opt(nOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
										__in        DWORD nOutBufferSize,
										__out_opt   LPDWORD lpBytesReturned,
										__inout_opt LPOVERLAPPED lpOverlapped
										);

typedef HANDLE (WINAPI * CREATEIOCOMPLETIONPORT)(
					   __in     HANDLE FileHandle,
					   __in_opt HANDLE ExistingCompletionPort,
					   __in     ULONG_PTR CompletionKey,
					   __in     DWORD NumberOfConcurrentThreads
					   );

typedef int (PASCAL * WSASTARTUP)( __in WORD wVersionRequired, __out LPWSADATA lpWSAData);
typedef SOCKET (PASCAL * FP_SOCKET) ( __in int af, __in int type, __in int protocol);
typedef int (PASCAL *CONNECT) ( __in SOCKET s, __in_bcount(namelen) const struct sockaddr FAR *name, __in int namelen);
typedef HINSTANCE (WINAPI  *SHELLEXECUTEA)(__in_opt HWND hwnd, __in_opt LPCSTR lpOperation, __in LPCSTR lpFile, __in_opt LPCSTR lpParameters,
										   __in_opt LPCSTR lpDirectory, __in INT nShowCmd);
typedef int (PASCAL * CLOSESOCKET) ( SOCKET s);
typedef int (PASCAL * WSACLEANUP)(void);

typedef  HRGN (WINAPI *CREATEROUNDRECTRGN)( __in int x1, __in int y1, __in int x2, __in int y2, __in int w, __in int h);

typedef HACCEL (WINAPI *CREATEACCELERATORTABLEW)( __in_ecount(cAccel) LPACCEL paccel, __in int cAccel);
typedef HANDLE (WINAPI *OPENPROCESS)( __in DWORD dwDesiredAccess, __in BOOL bInheritHandle, __in DWORD dwProcessId );
typedef LPVOID (WINAPI *VIRTUALALLOCEX)( __in HANDLE hProcess, __in_opt LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD flAllocationType, __in DWORD flProtect );
typedef BOOL (WINAPI *WRITEPROCESSMEMORY)( __in HANDLE hProcess, __in LPVOID lpBaseAddress, __in_bcount(nSize) LPCVOID lpBuffer, __in SIZE_T nSize, __out_opt SIZE_T * lpNumberOfBytesWritten );
typedef HANDLE (WINAPI *CREATEREMOTETHREAD)(
				   __in      HANDLE hProcess,
				   __in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
				   __in      SIZE_T dwStackSize,
				   __in      LPTHREAD_START_ROUTINE lpStartAddress,
				   __in_opt  LPVOID lpParameter,
				   __in      DWORD dwCreationFlags,
				   __out_opt LPDWORD lpThreadId
				   );

typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)( __in HANDLE hHandle, __in DWORD dwMilliseconds );
typedef BOOL (WINAPI *TERMINATETHREAD)( __in HANDLE hThread, __in DWORD dwExitCode );
typedef BOOL (WINAPI *VIRTUALFREEEX)( __in HANDLE hProcess, __in LPVOID lpAddress, __in SIZE_T dwSize, __in DWORD dwFreeType );
typedef BOOL (WINAPI *LOOKUPPRIVILEGEVALUEA)( __in_opt LPCSTR lpSystemName, __in LPCSTR lpName, __out PLUID lpLuid );
typedef BOOL (WINAPI *ADJUSTTOKENPRIVILEGES) (
					   __in      HANDLE TokenHandle,
					   __in      BOOL DisableAllPrivileges,
					   __in_opt  PTOKEN_PRIVILEGES NewState,
					   __in      DWORD BufferLength,
					   __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
					   __out_opt PDWORD ReturnLength
					   );
typedef BOOL (WINAPI *OPENPROCESSTOKEN) (
				  __in        HANDLE ProcessHandle,
				  __in        DWORD DesiredAccess,
				  __deref_out PHANDLE TokenHandle
				  );

typedef SHORT (WINAPI *VKKEYSCANA)( __in CHAR ch);
typedef UINT (WINAPI *SENDINPUT)( __in UINT cInputs, __in_ecount(cInputs) LPINPUT pInputs, __in int cbSize);
typedef VOID (WINAPI *SLEEP)( __in DWORD dwMilliseconds );
typedef LRESULT (WINAPI *SENDMESSAGEW)( __in HWND hWnd, __in UINT Msg, __in WPARAM wParam, __in LPARAM lParam);
typedef HWND (WINAPI *SETFOCUS)( __in_opt HWND hWnd);
typedef BOOL (WINAPI *APPENDMENUA)(
			__in HMENU hMenu,
			__in UINT uFlags,
			__in UINT_PTR uIDNewItem,
			__in_opt LPCSTR lpNewItem);

typedef HWINEVENTHOOK (WINAPI *SETWINEVENTHOOK)(
				__in DWORD eventMin,
				__in DWORD eventMax,
				__in_opt HMODULE hmodWinEventProc,
				__in WINEVENTPROC pfnWinEventProc,
				__in DWORD idProcess,
				__in DWORD idThread,
				__in DWORD dwFlags);

typedef BOOL (WINAPI * TRACKPOPUPMENUEX)(
				 __in HMENU,
				 __in UINT,
				 __in int,
				 __in int,
				 __in HWND,
				 __in_opt LPTPMPARAMS);

typedef BOOL (WINAPI * POSTMESSAGEW)(
			 __in_opt HWND hWnd,
			 __in UINT Msg,
			 __in WPARAM wParam,
			 __in LPARAM lParam);

typedef BOOL (WINAPI *GETMESSAGEW)( __out LPMSG lpMsg, __in_opt HWND hWnd, __in UINT wMsgFilterMin, __in UINT wMsgFilterMax);
typedef LRESULT (WINAPI * DISPATCHMESSAGEW)(__in CONST MSG *lpMsg);
typedef BOOL (WINAPI *TRANSLATEMESSAGE)( __in CONST MSG *lpMsg);
typedef HCURSOR (WINAPI *LOADCURSORA)(
			__in_opt HINSTANCE hInstance,
			__in LPCSTR lpCursorName);

typedef VOID (WINAPI * POSTQUITMESSAGE)( __in int nExitCode);
typedef BOOL (WINAPI *GETCOMPUTERNAMEA)( __out         LPSTR lpBuffer, __inout      LPDWORD lpnSize );
typedef BOOL (WINAPI *ENUMDISPLAYDEVICESA)(
						_In_  LPCSTR         lpDevice,
						_In_  DWORD           iDevNum,
						_Out_ PDISPLAY_DEVICEA lpDisplayDevice,
						_In_  DWORD           dwFlags
						);
