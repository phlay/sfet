
; Input:
;	RDI	buffer to burn
;	RSI	buffer length
;
	global	burn
burn:
	mov	rcx, rsi
	shr	rcx, 3
	xor	rax, rax
	rep	stosq

	mov	rcx, rsi
	and	rcx, 7
	rep	stosb

	ret
