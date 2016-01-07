#include "crt.h"

#pragma section("wineop", read, execute)
#pragma code_seg("wineop")

#pragma optimize("", off)

void __QUOTEPATH__(__in LPSTR lpStr)
{
	UINT n = __STRLEN__(lpStr);
	for (UINT i = n; i > 0; --i)
	{
		lpStr[i] = lpStr[i - 1];
	}
	lpStr[0] = lpStr[n+1] = '"';
}

BOOL __ISUPPER__(__in CHAR c) { return ('A' <= c) && (c <= 'Z'); };
CHAR __TOLOWER__(__in CHAR c) { return __ISUPPER__(c) ? c - 'A' + 'a' : c ; };

UINT __STRLEN__(__in LPCSTR lpStr1)
{
	UINT i = 0;
	while(lpStr1[i] != 0x0)
		i++;

	return i;
}

UINT __STRLENW__(__in LPWSTR lpStr1)
{
	UINT i = 0;
	while(lpStr1[i] != L'\0')
		i++;

	return i;
}

LPSTR __STRSTRI__(__in LPSTR lpStr1, __in LPSTR lpStr2)
{
	CHAR c = __TOLOWER__((lpStr2++)[0]);
	if (!c)
		return lpStr1;

	UINT dwLen = __STRLEN__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__((lpStr1++)[0]);
			if (!sc)
				return NULL;
		}
		while (sc != c);
	}
	while(__STRNCMPI__(lpStr1, lpStr2, dwLen) != 0);

	return (lpStr1 - 1); // FIXME: -0?
}

LPWSTR __STRSTRIW__(__in LPWSTR lpStr1, __in LPWSTR lpStr2)
{
	CHAR c = __TOLOWER__(((PCHAR)(lpStr2++))[0]);
	if (!c)
		return lpStr1;

	UINT dwLen = __STRLENW__(lpStr2);
	do
	{
		CHAR sc;
		do
		{
			sc = __TOLOWER__(((PCHAR)(lpStr1)++)[0]);
			if (!sc)
				return NULL;
		}
		while (sc != c);
	}
	while(__STRNCMPIW__(lpStr1, lpStr2, dwLen) != 0);

	return (lpStr1 - 1); // FIXME -2 ?
}

INT __STRCMPI__( __in LPSTR lpStr1, __in LPSTR lpStr2)
{
	int  v;
	CHAR c1, c2;
	do
	{
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		// The casts are necessary when pStr1 is shorter & char is signed 
		v = (UINT) __TOLOWER__(c1) - (UINT) __TOLOWER__(c2);
	}
	while ((v == 0) && (c1 != '\0') && (c2 != '\0') );
	return v;
}

INT __STRNCMPI__( __in LPSTR lpStr1, __in LPSTR lpStr2, __in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do
	{
		dwLen--;
		c1 = *lpStr1++;
		c2 = *lpStr2++;
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT) __TOLOWER__(c1) - (UINT) __TOLOWER__(c2);
	}
	while ((v == 0) && (c1 != '\0') && (c2 != '\0') && dwLen > 0);
	return v;
}

INT __STRNCMPIW__( __in LPWSTR lpStr1, __in LPWSTR lpStr2, __in DWORD dwLen)
{
	int  v;
	CHAR c1, c2;
	do {
		dwLen--;
		c1 = ((PCHAR)lpStr1++)[0];
		c2 = ((PCHAR)lpStr2++)[0];
		/* The casts are necessary when pStr1 is shorter & char is signed */
		v = (UINT) __TOLOWER__(c1) - (UINT) __TOLOWER__(c2);
	} while ((v == 0) && (c1 != 0x0) && (c2 != 0x0) && dwLen > 0);

	return v;
}

LPSTR __STRCAT__( __in LPSTR strDest, __in LPCSTR strSource)
{
	LPSTR d = strDest;
	LPSTR s = (LPSTR)strSource;

	while(*d) d++;

	do { *d++ = *s++; } while(*s);
	*d = 0x0;

	return strDest;
}

LPWSTR __STRCATW__( __in LPWSTR	strDest, __in LPWSTR strSource)
{
	LPWSTR d = strDest;
	LPWSTR s = strSource;

	while(*d != L'\0') d++;
	do { *d++ = *s++; } while (*s != L'\0');
	*d = L'\0';

	return strDest;
}

#pragma optimize( "", off ) 

LPVOID __MEMCPY__( __in LPVOID lpDst, __in LPVOID lpSrc, __in DWORD dwCount)
{
	LPBYTE s = (LPBYTE) lpSrc;
	LPBYTE d = (LPBYTE) lpDst;

	while (dwCount--)
		*d++ = *s++;

	return lpDst;
}

VOID __MEMSET__(__in LPVOID p, __in CHAR cValue, __in DWORD dwSize)
{
	for (UINT i=0; i<dwSize; i++)
		((PCHAR)p)[i] = cValue;
}

int __MEMCMP__( __in const void *buf1, __in const void *buf2, __in size_t count, __in BOOL bIgnoreCase /*= TRUE*/, __in unsigned char xorKey /*= 0*/ )
{
	LPBYTE s = (LPBYTE) buf1;
	LPBYTE d = (LPBYTE) buf2;

	while (count)
	{ 
		if (bIgnoreCase)
		{
			if (((*s)&0xdf) != (((*d) ^ xorKey)&0xdf) )
				return (int)(((*s)&0xdf) - (((*d) ^ xorKey) &0xdf));
		}
		else
		{
			if (*s != ((*d) ^ xorKey))
				return (int)((*s) - ((*d) ^ xorKey ));
		}
		s++;
		d++;
		count--;
	}

	return 0;
}

int __WMEMCMP__( __in const wchar_t * buf1, __in const wchar_t * buf2, __in size_t count, __in BOOL bIgnoreCase /*= TRUE*/, __in wchar_t xorKey /*= 0*/  )
{
	while (count)
	{
		if (bIgnoreCase)
		{
			if (((*buf1)&0xdf) != (((*buf2)^ xorKey)&0xdf) )
				return (int)(((*buf1)&0xdf) - (((*buf2)^ xorKey) &0xdf ));
		}
		else
		{
			if (*buf1 != ((*buf2)^ xorKey))
				return (int)((*buf1) - ((*buf2) ^ xorKey ));
		}
		buf1++;
		buf2++;
		count--;
	}

	return 0;
}

#pragma optimize("", on) 
char * DecryptString( __in LPVOID szString, __in size_t len, __in unsigned char key )
{
	unsigned char * s = (unsigned char *)szString;
	if (!s[len - 1]) return (char*)szString;
	while (len) s[--len] ^= key;
	return (char*)szString;
}
