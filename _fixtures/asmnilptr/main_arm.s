#include "textflag.h"

TEXT ·asmFunc(SB),0,$0-16
	MOVW arg+0(FP), R5
	MOVW (R5), R5
	MOVW R5, ret+8(FP)
	RET
