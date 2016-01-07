#pragma once
#include "ApiStub.h"
#include "EopUtilsType.h"
#ifdef __cplusplus
extern "C" {
#endif
	/************************************
	GetKernel32Module
	Search for kernel32 base in memory
	Return value: 
		Handle of kernel32.dll if found.
	*/
	HANDLE GetKernel32Module( void );

	/************************************
	GetProcAddr
	Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
	Parameter:
		__in HANDLE hModule
				A handle to the DLL module that contains the function or variable. T
		__in LPVOID lpProcName
				The function or variable name, or the function's ordinal value. 
		__in size_t count
				size of lpProcName
		__in unsigned char xorKey
				key to decrypt
	*/
	FARPROC WINAPI GetProcAddr( __in HANDLE hModule, __in LPVOID lpProcName, __in size_t count, __in unsigned char xorKey = 0 );

	/************************************
	Get All functions 
	__in LPENVIRONMENT environment
		A pointer to API Function table
	*/
	BOOL GetApiFunctions( __inout LPENVIRONMENT environment );
	BOOL    WINAPI GetFunctionStub( __in HMODULE hKernel32, __inout LPENVIRONMENT environment );

	/************************************
	Patch pointer in memory with specified tag
	Parameter: 
		__in LPENVIRONMENT lpEnv
			A pointer to API Function table
		__in LPVOID lpFunction
			Function to patch
		__in DWORD_PTR tag
			tag to replace
	*/
	BOOL    WINAPI FixPointer(__in LPENVIRONMENT lpEnv, __in LPVOID lpFunction, __in DWORD_PTR tag);

#ifdef __cplusplus
}
#endif

#ifdef _M_IX86
#define __InterlockedExchangePointer__(env, Target, Value) \
			CWA(env, InterlockedExchange)((PLONG)Target, (LONG)Value)
#else
#define __InterlockedExchangePointer__(env, Target, Value) \
			InterlockedExchangePointer(Target, Value)
#endif