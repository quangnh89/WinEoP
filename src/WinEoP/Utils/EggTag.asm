IFDEF I386
.586
.model flat, stdcall
ENDIF

.code wineop
IFDEF I386
EggTag PROC public 
	db 'Tx86Tx86'
EggTag ENDP

ELSEIFDEF AMD64

EggTag PROC  public 
	db 'Tx64Tx64'
EggTag ENDP

ENDIF

END 