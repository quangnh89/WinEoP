IFDEF I386
.586
.model flat, stdcall
ENDIF

.code wineop
IFDEF I386
IsKernelMode PROC public 
	xor    eax, eax
	mov	   ax, cs
	cmp    ax, 8h ; kernel mode ?
	sete   al
	movzx  eax, al
	ret
IsKernelMode ENDP


;BOOL NTAPI NtUserDefSetText(__in HWND hwnd, __in LPVOID pstrText)
NtUserDefSetText PROC hwnd:DWORD, pstrText:DWORD
	push   ebp
	mov    ebp, esp
	push   dword ptr [ebp + 8]
	push   dword ptr [ebp + 12]
	mov    eax, 116Dh
	mov    edx, 7FFE0300h 
	call   dword ptr [edx]
	leave
	ret    8

NtUserDefSetText ENDP
		
ELSEIFDEF AMD64

IsKernelMode PROC  public 
	xor    rax, rax
	mov	   ax, cs
	cmp    ax, 10h ; kernel mode ?
	sete   al
	movzx  eax, al
	ret
IsKernelMode ENDP

ENDIF

END 