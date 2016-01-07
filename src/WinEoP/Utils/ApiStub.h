#pragma once
#include "winapi.h"

// define function pointers
typedef struct _WINAPI_TABLE
{
	// # alway kernel32 first!!

	// kernel32.dll
	LOADLIBRARYA    		  LoadLibraryA;
	LOADLIBRARYW    		  LoadLibraryW;
	LOADLIBRARYEXA  		  LoadLibraryExA;
	GETPROCADDRESS  		  GetProcAddress;
	VIRTUALPROTECT  		  VirtualProtect;
	VIRTUALQUERY			  VirtualQuery;
	VIRTUALALLOC  			  VirtualAlloc;
	VIRTUALFREE				  VirtualFree;
	ISWOW64PROCESS  		  IsWow64Process;
	CREATETOOLHELP32SNAPSHOT  CreateToolhelp32Snapshot;
	PROCESS32FIRSTW 		  Process32FirstW;
	PROCESS32NEXTW  		  Process32NextW;
	CLOSEHANDLE     		  CloseHandle;
	GETCURRENTPROCESSID       GetCurrentProcessId;
	EXPANDENVIRONMENTSTRINGSA ExpandEnvironmentStringsA;
	CREATEPROCESSA			  CreateProcessA;
	GETVERSIONEXA             GetVersionExA;
	GETCURRENTPROCESS         GetCurrentProcess;
	GLOBALALLOC				  GlobalAlloc;
	GETMODULEHANDLEA		  GetModuleHandleA;
	GLOBALFREE				  GlobalFree;
	FREELIBRARY				  FreeLibrary;
	SETLASTERROR			  SetLastError;
	GETLASTERROR			  GetLastError;
	ISBADREADPTR			  IsBadReadPtr;
	GETCURRENTTHREADID		  GetCurrentThreadId;
#ifdef _M_IX86
	INTERLOCKEDEXCHANGE	      InterlockedExchange;
#endif
	DEVICEIOCONTROL			  DeviceIoControl;
	CREATEIOCOMPLETIONPORT	  CreateIoCompletionPort;
	OPENPROCESS               OpenProcess;
	VIRTUALALLOCEX			  VirtualAllocEx;
	WRITEPROCESSMEMORY		  WriteProcessMemory;
	CREATEREMOTETHREAD		  CreateRemoteThread;
	WAITFORSINGLEOBJECT	      WaitForSingleObject;
	TERMINATETHREAD			  TerminateThread;
	VIRTUALFREEEX			  VirtualFreeEx;
	SLEEP					  Sleep;
	GETCOMPUTERNAMEA		  GetComputerNameA;

	// Advapi32
	REGOPENKEYEXA			 RegOpenKeyExA;
	REGQUERYVALUEEXA		 RegQueryValueExA;
	REGCLOSEKEY				 RegCloseKey;
	OPENPROCESSTOKEN		 OpenProcessToken;
	LOOKUPPRIVILEGEVALUEA	 LookupPrivilegeValueA;
	ADJUSTTOKENPRIVILEGES	 AdjustTokenPrivileges;

	// user32.dll
	REGISTERCLASSA			 RegisterClassA;
	REGISTERCLASSEXA		 RegisterClassExA;
	CREATEWINDOWEXA          CreateWindowExA;
	UNREGISTERCLASSA		 UnregisterClassA;
	DESTROYWINDOW			 DestroyWindow;
	SETWINDOWSHOOKEXA		 SetWindowsHookExA;
	SETFOREGROUNDWINDOW	     SetForegroundWindow;
	TRACKPOPUPMENU			 TrackPopupMenu;
	POSTMESSAGEA			 PostMessageA;
	UNHOOKWINDOWSHOOK		 UnhookWindowsHook;
	DESTROYMENU				 DestroyMenu;
	SETWINDOWLONGA			 SetWindowLongA;
	CALLNEXTHOOKEX			 CallNextHookEx;
	CREATEPOPUPMENU			 CreatePopupMenu;
	INSERTMENUITEMA			 InsertMenuItemA;
	CALLWINDOWPROCA			 CallWindowProcA;
	ENDMENU					 EndMenu;
	DEFWINDOWPROCA			 DefWindowProcA;
	LOADICONA				 LoadIconA;
	SETCLASSLONGA			 SetClassLongA;
	ENUMPROPSEXA	 		 EnumPropsExA;
	REMOVEPROPA				 RemovePropA;
	WSPRINTFA				 wsprintfA;
	SETPROPA				 SetPropA;
	CREATEACCELERATORTABLEW  CreateAcceleratorTableW;
	VKKEYSCANA				 VkKeyScanA;
	SENDINPUT				 SendInput;
	SENDMESSAGEW			 SendMessageW;
	SETFOCUS				 SetFocus;
	APPENDMENUA				 AppendMenuA;
	SETWINEVENTHOOK			 SetWinEventHook;
	TRACKPOPUPMENUEX		 TrackPopupMenuEx;
	POSTMESSAGEW			 PostMessageW;
	GETMESSAGEW				 GetMessageW;
	DISPATCHMESSAGEW		 DispatchMessageW;
	TRANSLATEMESSAGE		 TranslateMessage;
	LOADCURSORA				 LoadCursorA;
	POSTQUITMESSAGE			 PostQuitMessage;
	ENUMDISPLAYDEVICESA		 EnumDisplayDevicesA;

	// Ws2_32.dll
	WSASTARTUP				WSAStartup;
	WSACLEANUP				WSACleanup;
	FP_SOCKET				socket;
	CLOSESOCKET				closesocket;
	CONNECT					connect;

	// shell32.dll
	SHELLEXECUTEA			ShellExecuteA;

	// Gdi32.dll
	CREATEROUNDRECTRGN		CreateRoundRectRgn;

	// Ntdll.dll
	ZWQUERYSYSTEMINFORMATION		ZwQuerySystemInformation;
	ZWALLOCATEVIRTUALMEMORY			ZwAllocateVirtualMemory;
	NTCREATEWORKERFACTORY			NtCreateWorkerFactory;
	NTSETINFORMATIONWORKERFACTORY	NtSetInformationWorkerFactory;
	NTQUERYINFORMATIONWORKERFACTORY NtQueryInformationWorkerFactory;
	NTQUERYEAFILE					NtQueryEaFile;
	NTQUERYINTERVALPROFILE			NtQueryIntervalProfile;

	// **leave**
	PSLOOKUPPROCESSBYPROCESSID		PsLookupProcessByProcessId;

}WINAPI_TABLE, *LPWINAPI_TABLE;
typedef const LPWINAPI_TABLE LPCWINAPI_TABLE;
