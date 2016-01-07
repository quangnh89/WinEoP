#pragma once

#define XOR_KEY (0x89)

typedef struct STRING_TABLE
{
	char strSOFTWARE_Microsoft_Windows_NT_CurrentVersion[48];
	char strCurrentVersion[15];
	char strcomspec[12];
	char struser32[11];

	// -- [Auto generated] BEGIN --
unsigned char strLoadLibraryA[13];
unsigned char strLoadLibraryW[13];
unsigned char strLoadLibraryExA[15];
unsigned char strGetProcAddress[15];
unsigned char strVirtualProtect[15];
unsigned char strVirtualQuery[13];
unsigned char strVirtualAlloc[13];
unsigned char strVirtualFree[12];
unsigned char strIsWow64Process[15];
unsigned char strCreateToolhelp32Snapshot[25];
unsigned char strProcess32FirstW[16];
unsigned char strProcess32NextW[15];
unsigned char strCloseHandle[12];
unsigned char strGetCurrentProcessId[20];
unsigned char strExpandEnvironmentStringsA[26];
unsigned char strCreateProcessA[15];
unsigned char strGetVersionExA[14];
unsigned char strGetCurrentProcess[18];
unsigned char strGlobalAlloc[12];
unsigned char strGetModuleHandleA[17];
unsigned char strGlobalFree[11];
unsigned char strFreeLibrary[12];
unsigned char strSetLastError[13];
unsigned char strGetLastError[13];
unsigned char strIsBadReadPtr[13];
unsigned char strGetCurrentThreadId[19];
unsigned char strInterlockedExchange[20];
unsigned char strDeviceIoControl[16];
unsigned char strCreateIoCompletionPort[23];
unsigned char strOpenProcess[12];
unsigned char strVirtualAllocEx[15];
unsigned char strWriteProcessMemory[19];
unsigned char strCreateRemoteThread[19];
unsigned char strWaitForSingleObject[20];
unsigned char strTerminateThread[16];
unsigned char strVirtualFreeEx[14];
unsigned char strSleep[6];
unsigned char strGetComputerNameA[17];
unsigned char strAdvapi32[9];
unsigned char strRegOpenKeyExA[14];
unsigned char strRegQueryValueExA[17];
unsigned char strRegCloseKey[12];
unsigned char strOpenProcessToken[17];
unsigned char strLookupPrivilegeValueA[22];
unsigned char strAdjustTokenPrivileges[22];
unsigned char struser32_dll[11];
unsigned char strRegisterClassA[15];
unsigned char strRegisterClassExA[17];
unsigned char strCreateWindowExA[16];
unsigned char strUnregisterClassA[17];
unsigned char strDestroyWindow[14];
unsigned char strSetWindowsHookExA[18];
unsigned char strSetForegroundWindow[20];
unsigned char strTrackPopupMenu[15];
unsigned char strPostMessageA[13];
unsigned char strUnhookWindowsHook[18];
unsigned char strDestroyMenu[12];
unsigned char strSetWindowLongA[15];
unsigned char strCallNextHookEx[15];
unsigned char strCreatePopupMenu[16];
unsigned char strInsertMenuItemA[16];
unsigned char strCallWindowProcA[16];
unsigned char strEndMenu[8];
unsigned char strDefWindowProcA[15];
unsigned char strLoadIconA[10];
unsigned char strSetClassLongA[14];
unsigned char strEnumPropsExA[13];
unsigned char strRemovePropA[12];
unsigned char strwsprintfA[10];
unsigned char strSetPropA[9];
unsigned char strCreateAcceleratorTableW[24];
unsigned char strVkKeyScanA[11];
unsigned char strSendInput[10];
unsigned char strSendMessageW[13];
unsigned char strSetFocus[9];
unsigned char strAppendMenuA[12];
unsigned char strSetWinEventHook[16];
unsigned char strTrackPopupMenuEx[17];
unsigned char strPostMessageW[13];
unsigned char strGetMessageW[12];
unsigned char strDispatchMessageW[17];
unsigned char strTranslateMessage[17];
unsigned char strLoadCursorA[12];
unsigned char strPostQuitMessage[16];
unsigned char strEnumDisplayDevicesA[20];
unsigned char strWs2_32_dll[11];
unsigned char strWSAStartup[11];
unsigned char strWSACleanup[11];
unsigned char strsocket[7];
unsigned char strclosesocket[12];
unsigned char strconnect[8];
unsigned char strshell32_dll[12];
unsigned char strShellExecuteA[14];
unsigned char strGdi32_dll[10];
unsigned char strCreateRoundRectRgn[19];
unsigned char strNtdll_dll[10];
unsigned char strZwQuerySystemInformation[25];
unsigned char strZwAllocateVirtualMemory[24];
unsigned char strNtCreateWorkerFactory[22];
unsigned char strNtSetInformationWorkerFactory[30];
unsigned char strNtQueryInformationWorkerFactory[32];
unsigned char strNtQueryEaFile[14];
unsigned char strNtQueryIntervalProfile[23];
	// -- [Auto generated] END --


}STRING_TABLE, *LPSTRING_TABLE;
