; optimization ideas:
;   - push and pop is slow, maybe don't cache Key20Ri and instead
;     calculate them with (compiled 14 bytes each):
;	mov rax, KeyRi
;	shl rax, 2
;	add rax, KeyRi
;	shl rax, 2
;     KeyR0 and KeyR1 could be renamed in tmpA and tmpB
;   - rax, rbx, rdx, r14 and 15 would be free than
;   - test if lods instructions are slow and replace them if needed
;   - use sse instructions
;   - use rbp for pointing to context?
;


%define state0	R8
%define state1	R9
%define state2	R10

%define KeyR0	R11
%define KeyR1	R12
%define KeyR2	R13
%define Key20R1	R14
%define Key20R2	R15



;
; WARNING: this structure MUST be kept in sync with 'struct poly1305'
; in poly1305.h
;
struc	context
	.state0		resq	1
	.state1		resq	1
	.state2		resq	1

	.KeyR0		resq	1
	.KeyR1		resq	1
	.KeyR2		resq	1
	.Key20R1	resq	1
	.Key20R2	resq	1

	.buffer		resb	17
	.fill		resq	1
endstruc




;
; mulr - performs: state <- (state * r) mod 2^130-5
;
; Changes: rax, rbx, rcx, state0, state1, state2
;
; expects:
;	rbp					0xfffffffffff
;	state0 + state1*2^44 + state2*2^88	state
;	KeyR0 + KeyR1*2^44 + KeyR2*2^88		r
;	Key20R1					20*KeyR1
;	Key20R2					20*KeyR2
;
%macro	mulr	0
	push	rdx

	; we use rcx:rbx as 128bit carry register

	; carry <- limb0 = state0*r0 + 20*state1*r2 + 20*state2*r1
	mov	rax, state0
	mul	KeyR0
	mov	rbx, rax
	mov	rcx, rdx

	mov	rax, state1
	mul	Key20R2
	add	rbx, rax
	adc	rcx, rdx

	mov	rax, state2
	mul	Key20R1
	add	rbx, rax
	adc	rcx, rdx

	; save 44 lower bits of limb0 on stack
	mov	rax, rbx
	and	rax, rbp
	push	rax

	; carry >>= 44
	shr	rbx, 44
	mov	rax, rcx
	shl	rax, 20
	or	rbx, rax
	shr	rcx, 44



	; carry <- limb1 = carry + state0*r1 + state1*r0 + 20*state2*r2
	mov	rax, state0
	mul	KeyR1
	add	rbx, rax
	adc	rcx, rdx

	mov	rax, state1
	mul	KeyR0
	add	rbx, rax
	adc	rcx, rdx

	mov	rax, state2
	mul	Key20R2
	add	rbx, rax
	adc	rcx, rdx

	; store lower 44 bit of limb1 onto stack
	mov	rax, rbx
	and	rax, rbp
	push	rax

	; carry >>= 44
	shr	rbx, 44
	mov	rax, rcx
	shl	rax, 20
	or	rbx, rax
	shr	rcx, 44


	; carry <- limb2 = carry + state0*r2 + state1*r1 + state2*r0
	mov	rax, state0
	mul	KeyR2
	add	rbx, rax
	adc	rcx, rdx

	mov	rax, state1
	mul	KeyR1
	add	rbx, rax
	adc	rcx, rdx

	mov	rax, state2
	mul	KeyR0
	add	rbx, rax
	adc	rcx, rdx

	; state2 <- lower 42 bits of carry
	mov	state2, rbx
	mov	rax, rbp
	shr	rax, 2
	and	state2, rax
	pop	state1
	pop	state0

	; state0 +=  5*(carry >> 42)
	shr	rbx, 42
	shl	rcx, 22
	or	rbx, rcx
	add	state0, rbx
	shl	rbx, 2
	add	state0, rbx

	pop	rdx
%endmacro



;; Input:
;;	RDI	context
;;	RSI	r
;;
	global	poly1305_init
poly1305_init:
	cld

	mov	r10, 0xfffffffffff


	; rax <- clamped lower 64 bit of r
	lodsq
	mov	r11, 0x0ffffffc0fffffff
	and	rax, r11

	; context.KeyR0 <- bits [0,44) of r
	mov	r8, rax
	and	r8, r10
	mov	[rdi + context.KeyR0], r8

	; r8 <- unused 20 bits of lower part of r
	mov	r8, rax
	shr	r8, 44


	; rax <- clamped upper 64 bits of r
	lodsq
	mov	r11, 0x0ffffffc0ffffffc
	and	rax, r11

	; context.KeyR1 <- bits [44,88) of r
	mov	r9, rax
	shl	r9, 20
	or	r8, r9
	and	r8, r10
	mov	[rdi + context.KeyR1], r8

	; context.KeyR2 <- bits [88,128) of r
	shr	rax, 24
	mov	[rdi + context.KeyR2], rax


	; context.Key20R2 <- 20*KeyR2
	shl	rax, 2
	mov	rcx, rax
	shl	rax, 2
	add	rax, rcx
	mov	[rdi + context.Key20R2], rax

	; context.Key20R1 <- 20*KeyR1
	shl	r8, 2
	mov	rax, r8
	shl	r8, 2
	add	rax, r8
	mov	[rdi + context.Key20R1], rax


	; context.status <- 0
	xor	rax, rax
	mov	[rdi + context.state0], rax
	mov	[rdi + context.state1], rax
	mov	[rdi + context.state2], rax

	; context.fill <- 0
	mov	[rdi + context.fill], rax
	ret


;; Input:
;;	RDI	ctx
;;	RSI	data
;;	RDX	len
;;
	global	poly1305_update
poly1305_update:
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15

	cld

	; load state
	mov	state0, [rdi + context.state0]
	mov	state1, [rdi + context.state1]
	mov	state2, [rdi + context.state2]

	; load key
	mov	KeyR0, [rdi + context.KeyR0]
	mov	KeyR1, [rdi + context.KeyR1]
	mov	KeyR2, [rdi + context.KeyR2]
	mov	Key20R1, [rdi + context.Key20R1]
	mov	Key20R2, [rdi + context.Key20R2]

	; 44bit mask
	mov	rbp, 0xfffffffffff


	; do we have data in internal buffer?
	mov	rcx, [rdi + context.fill]
	or	rcx, rcx
	je	update_reload_data

	;
	; fill up internal buffer
	;

	; rbp <- current buffer position
	lea	rbp, [rdi + context.buffer + rcx]

	; rcx <- needed bytes = 16 - rcx
	neg	rcx
	add	rcx, 16

	; we need rcx bytes, do we have that much?
	cmp	rcx, rdx
	jbe	update_fillup

	; copy what we have and go home...
	add	[rdi + context.fill], rdx
	mov	rdi, rbp
	mov	rcx, rdx
	rep	movsb
	jmp	update_return


update_fillup:
	sub	rdx, rcx

	xchg	rdi, rbp
	rep	movsb
	mov	rdi, rbp

	; add data from internal buffer to state
	mov	rbp, 0xfffffffffff

	mov	rax, [rdi + context.buffer]
	mov	rbx, rax
	and	rax, rbp
	add	state0, rax

	mov	rax, [rdi + context.buffer + 8]
	mov	rcx, rax
	shl	rax, 20
	shr	rbx, 44
	or	rax, rbx
	and	rax, rbp
	add	state1, rax

	shr	rcx, 24
	add	state2, rcx


update_mul_r:
	; add 2^128 padding to state
	;xor	rcx, rcx
	;inc	rcx
	;shl	rcx, 40
	mov	rcx, 0x10000000000
	add	state2, rcx

	mulr

update_reload_data:
	cmp	rdx, 16
	jb	update_final


	; load next data and add it to state
	lodsq
	mov	rbx, rax
	and	rax, rbp
	add	state0, rax

	lodsq
	mov	rcx, rax
	shl	rax, 20
	shr	rbx, 44
	or	rax, rbx
	and	rax, rbp
	add	state1, rax

	shr	rcx, 24
	add	state2, rcx

	sub	rdx, 16
	jmp	update_mul_r


update_final:
	; write state to context
	mov	[rdi + context.state0], state0
	mov	[rdi + context.state1], state1
	mov	[rdi + context.state2], state2

	; save remaining data to internal buffer
	mov	[rdi + context.fill], rdx
	add	rdi, context.buffer
	mov	rcx, rdx
	rep	movsb

update_return:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp

	ret

;
; carry_reduce - performs one carry-reduce round for state
;
; assumes:
;	rcx = 2^45-1 = 0xfffffffffff
;	r11 = 2^43-1 = 0x3ffffffffff
;
%macro carry_reduce	0
	mov	rax, state0
	shr	rax, 44
	and	state0, rcx

	add	state1, rax
	mov	rax, state1
	shr	rax, 44
	and	state1, rcx

	add	state2, rax
	mov	rax, state2
	shr	rax, 42
	and	state2, r11

	; state0 += 5*rax
	add	state0, rax
	shl	rax, 2
	add	state0, rax
%endmacro




;; Input:
;;	RDI	context
;;	RSI	encno
;;	RDX	mac
;;
	global	poly1305_mac
poly1305_mac:
	cld

	; load state
	mov	state0, [rdi + context.state0]
	mov	state1, [rdi + context.state1]
	mov	state2, [rdi + context.state2]

	; do we have data left in internal buffer?
	mov	rcx, [rdi + context.fill]
	or	rcx, rcx
	jz	mac_finalize

	;
	; handle internal buffer
	;
	push	rbp
	push	rbx
	push	r12
	push	r13
	push	r14
	push	r15

	lea	rbp, [rdi + context.buffer + rcx]

	; padding
	mov	byte [rbp], 1
	inc	rbp

	; rcx <- unused bytes in buffer = 16 - rcx - 1
	neg	rcx
	add	rcx, 15

	; zero unsed buffer space
	xor	al, al
	xchg	rdi, rbp
	rep	stosb
	mov	rdi, rbp


	; add data from internal buffer to state
	mov	rbp, 0xfffffffffff

	mov	rax, [rdi + context.buffer]
	mov	rbx, rax
	and	rax, rbp
	add	state0, rax

	mov	rax, [rdi + context.buffer + 8]
	mov	rcx, rax
	shl	rax, 20
	shr	rbx, 44
	or	rax, rbx
	and	rax, rbp
	add	state1, rax

	shr	rcx, 24
	add	state2, rcx

	; load key
	mov	KeyR0, [rdi + context.KeyR0]
	mov	KeyR1, [rdi + context.KeyR1]
	mov	KeyR2, [rdi + context.KeyR2]
	mov	Key20R1, [rdi + context.Key20R1]
	mov	Key20R2, [rdi + context.Key20R2]

	mulr

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	pop	rbp


mac_finalize:
	;
	; completly reduce state
	;
	mov	rcx, 0xfffffffffff
	mov	r11, rcx
	shr	r11, 2

	add	state0, 5
	carry_reduce
	carry_reduce
	sub	state0, 5
	carry_reduce

	;
	; compress state to state0 and state1
	;
	mov	rax, state1
	shl	rax, 44
	or	state0, rax
	shr	state1, 20
	shl	state2, 24
	or	state1, state2

	;
	; add encrypted nonce to state
	;
	lodsq
	add	state0, rax
	lodsq
	adc	state1, rax

	;
	; export final poly1305 mac
	;
	mov	[rdx], state0
	mov	[rdx + 8], state1

	ret
