#pragma once
#include "winapi.h"

typedef struct APIFUNCS
{
	GETPROCADDRESS GetProcAddress;
	VIRTUALPROTECT VirtualProtect;
	VIRTUALQUERY   VirtualQuery;
	ISBADREADPTR   IsBadReadPtr;
}APIFUNCS;

#ifdef __cplusplus
extern "C" {
#endif

	// entry point
	void EggHunting( void );
	
	/************************************
	EggIsUnreadablePage
	Verifies that the calling process has read access to the specified page.
	
	Parameter: 
	__in APIFUNCS * lpApi
			API Function table
	
	__in void * ptr
			A pointer to the first byte of the memory block.

	Return value:
		If the calling process has read access to all bytes in the specified memory range, the return value is non-zero.
	*/
	BOOL EggIsUnreadablePage( __in APIFUNCS *lpApi, __in void *ptr);


	/************************************
	EggScanTag
	Search for specific tagged memory
	Parameter: 
		__in APIFUNCS * lpApi
				API Function table
		__in DWORD dwTag
				TAG 
		__in ULONG_PTR p
			A pointer to the first byte of the memory block to search.
	Return value:
		If the calling process has found specific memory with tag access, the return value is the address of memory block.
		If the calling process has not found specific memory, the return value is NULL.
	*/
	LPVOID EggScanTag( __in APIFUNCS *lpApi, __in DWORD dwTag, __in ULONG_PTR p = 0x1000 );


	/************************************
	GetStringHash
	Calculate hash of string
	Parameter: 
		__in LPVOID lpBuffer
				A pointer to the buffer
		__in BOOL bUnicode
				Character is unicode or not
		__in UINT uLen
				Buffer size in characters
	Return value: 
		Hash of the string
	*/
	DWORD GetStringHash( __in LPVOID lpBuffer, __in BOOL bUnicode, __in UINT uLen);


	/************************************
	EggGetKernel32Handle
	Search for kernel32 base in memory
	Return value: 
		Handle of kernel32.dll if found.
		If the function fails, the return value is INVALID_HANDLE_VALUE. 
	*/
	HANDLE EggGetKernel32Handle();

	/************************************
	EggGetProcAddr
	Search for GetProcAddress function address from kernel32.dll.
	Parameter:
		fpGetProcAddress 
			a variable to store function address

	Return value: 
		If the function succeeds, the return value is the non-zero.
		If the function fails, the return value is Zero. 
	*/
	BOOL EggGetProcAddr( __out GETPROCADDRESS *fpGetProcAddress );

#ifdef __cplusplus
}
#endif
