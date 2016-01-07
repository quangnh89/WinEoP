#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
	// Determines whether the specified process is running under Kernelmode.
	BOOL __stdcall IsKernelMode( void );

	BOOL NTAPI NtUserDefSetText(__in HWND hwnd, __in LPVOID pstrText);

#ifdef __cplusplus
};
#endif
