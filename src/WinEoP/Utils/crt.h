#pragma once
#include <WTypes.h>

#define __SUB_ABS__(type, a, b) ((type) ( (type)a > (type)b ? ((type)a - (type)b) : ((type)b - (type)a))) 

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

	/************************************
	__QUOTEPATH__
	The entire path is enclosed in quotation marks.
	Parameter: 
		__in LPSTR lpStr
			A pointer to a null-terminated string that contains the path to search.
	*/
	void __QUOTEPATH__(__in LPSTR lpStr);

	/************************************
	__MEMCPY__
	Copies bytes between buffers. 
	Parameter: 
	    __in LPVOID lpDst : New buffer.
		__in LPVOID lpSrc: Buffer to copy from.
		__in DWORD dwCount : Number of characters to copy. */
	LPVOID __MEMCPY__( __in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount);

	/************************************
	__ISUPPER__
	Tests whether an element in a locale is in upper case.
	Parameter:
		__in CHAR c
			The element to be tested. */
	BOOL __ISUPPER__( __in CHAR c );

	/************************************
	__TOLOWER__
	Converts a character to lowercase.
	Parameter: 
		CHAR c
			Character to convert.
	*/
	CHAR __TOLOWER__( __in CHAR c );

	/************************************
	__STRLEN__ (ANSI version)
	Get the length of a string
	Parameter: __in LPCSTR lpStr1 : Null-terminated string.

	Return Values
		Returns the number of characters in string
	*/
	UINT __STRLEN__( __in LPCSTR lpStr1 );

	/************************************
	__STRLENW__ (UNICODE version)
	Get the length of a string
	Parameter: 
		__in LPCSTR lpStr1
			Null-terminated string.

	Return Values
		Returns the number of characters in string
	*/
	UINT __STRLENW__( __in LPWSTR lpStr1 );

	/************************************
	__STRCMPI__ ANSI version
	Perform a lowercase comparison of strings.
	Parameter: 
		__in LPSTR lpStr1
			Null-terminated strings to compare.
		__in LPSTR lpStr2
			Null-terminated strings to compare.

	Return Value:
	< 0  buf1 less than buf2
	0    buf1 identical to buf2
	> 0  buf1 greater than buf2
	*/
	INT __STRCMPI__( __in LPSTR lpStr1, __in LPSTR lpStr2 );

	/************************************
	__STRSTRI__
	Finds the first occurrence of a substring within a string.
	Parameter: 
	__in LPSTR lpStr1
			The address of the null-terminated string being searched.

	__in LPSTR lpStr2
			The substring to search for.
	
	Returns the address of the first occurrence of the matching substring if successful, or NULL otherwise. 
	*/
	LPSTR __STRSTRI__(
		__in LPSTR lpStr1,
		__in LPSTR lpStr2
		);

	/************************************
	__STRSTRIW__ UNICODE version
	Perform a lowercase comparison of strings.
	Parameter: 
		__in LPSTR lpStr1
			Null-terminated strings to compare.
		__in LPSTR lpStr2
			Null-terminated strings to compare.
	Returns the address of the first occurrence of the matching substring if successful, or NULL otherwise. 
	*/
	LPWSTR __STRSTRIW__(
		__in LPWSTR lpStr1,
		__in LPWSTR lpStr2
		);

	/************************************
	__STRNCMPI__ ANSI version
	Compare characters of two strings without regard to case.
	Parameter:
		lpStr1, lpStr2
			Null-terminated strings to compare.
		dwLen
			Number of characters to compare.
	Return Value:
	< 0  buf1 less than buf2
	0    buf1 identical to buf2
	> 0  buf1 greater than buf2
	*/
	INT __STRNCMPI__(
		__in LPSTR lpStr1,
		__in LPSTR lpStr2,
		__in DWORD dwLen
		);

	/************************************
	__STRNCMPI__ UNICODE version
	Compare characters of two strings without regard to case.
	Parameter:
		lpStr1, lpStr2
			Null-terminated strings to compare.
		dwLen
			Number of characters to compare.

	Return Value:
	< 0  buf1 less than buf2
	0    buf1 identical to buf2
	> 0  buf1 greater than buf2
	*/
	INT __STRNCMPIW__(
		__in LPWSTR lpStr1,
		__in LPWSTR lpStr2,
		__in DWORD dwLen
		);

	/************************************
	__STRCATW__ ANSI VERSION
	Append a string.
	Parameter: 
		strDest 
			Null-terminated destination string. 
		strSource 
			Null-terminated source string. 
	Returns the destination string (strDestination). No return value is reserved to indicate an error.
	*/
	LPSTR __STRCAT__( __in LPSTR strDest, __in LPCSTR strSource);

	/************************************
	__STRCATW__ UNICODE VERSION
	Append a string.
	Parameter: 
		strDest 
			Null-terminated destination string. 
		strSource 
			Null-terminated source string. 
	returns the destination string (strDestination). No return value is reserved to indicate an error.
	*/
	LPWSTR __STRCATW__(
		__in LPWSTR	strDest,
		__in LPWSTR strSource
		);

	/************************************
	__MEMSET__
	Sets buffers to a specified character.
	Parameter: 
		LPVOID p
			Pointer to destination.

		CHAR cValue 
			Character to set.

		DWORD dwSize 
			Number of characters.
	*/
	VOID __MEMSET__(
		__in LPVOID p,
		__in CHAR cValue,
		__in DWORD dwSize
		);

	/************************************
	__MEMCMP__
	Compare characters in two buffers.
	Parameter: 
	__in const void * buf1
			First buffer.
	__in const void * buf2
			Second buffer
	__in size_t count
			Number of characters (bytes for __MEMCMP__, wide characters for __WMEMCMP__).
	__in BOOL bIgnoreCase	
			IgnoreCase	
	__in unsigned char xorKey 
	key for decrypt buffer
	
	Return Value:
	 < 0  buf1 less than buf2
       0  buf1 identical to buf2
  	 > 0  buf1 greater than buf2
	*/
	int __MEMCMP__( __in const void *buf1, __in const void *buf2, __in size_t count, __in BOOL bIgnoreCase = TRUE, __in unsigned char xorKey = 0 );

	int __WMEMCMP__( __in const wchar_t * buf1, __in const wchar_t * buf2, __in size_t count, __in BOOL bIgnoreCase = TRUE, __in wchar_t xorKey = 0 );

	/************************************
	DecryptString
	XOR-based decrypt buffer
	Parameter: 
		__in LPVOID szString
			Pointer to destination.

		__in size_t len
			Number of characters.

		__in unsigned char key
			key for decrypt buffer
	Return Value:
		Decrypted string
	*/
	char * DecryptString( __in LPVOID szString, __in size_t len, __in unsigned char key);

#ifdef __cplusplus
}
#endif // __cplusplus
