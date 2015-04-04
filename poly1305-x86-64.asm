%use smartalign

alignmode p6


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

	.secret		resb	16

	.buffer		resb	17
	.fill		resb	1
endstruc




;
; mulr - performs: state <- (state * r) mod 2^130-5
;
; Changes: rax, rbx, rcx, rdx, state0, state1, state2
;
; expects:
;	mask					0xfffffffffff
;	state0 + state1*2^44 + state2*2^88	state
;	KeyR0 + KeyR1*2^44 + KeyR2*2^88		r
;	Key20R1					20*KeyR1
;	Key20R2					20*KeyR2
;

%define state0	r8
%define state1	r9
%define state2	r10

%define mask	r11

%define KeyR0	xmm3
%define KeyR1	xmm4
%define KeyR2	xmm5
%define Key20R1	xmm6
%define Key20R2	xmm7

%macro	mulr	0
	; we use rcx:rbx as 128bit carry register

	; carry <- limb0 = state0*r0 + 20*state1*r2 + 20*state2*r1
	movq	rax, KeyR0
	mul	state0
	mov	rbx, rax
	mov	rcx, rdx

	movq	rax, Key20R2
	mul	state1
	add	rbx, rax
	adc	rcx, rdx

	movq	rax, Key20R1
	mul	state2
	add	rbx, rax
	adc	rcx, rdx

	; save 44 lower bits of limb0 on stack
	mov	rax, rbx
	and	rax, mask
	push	rax

	; carry >>= 44
	shr	rbx, 44
	mov	rax, rcx
	shl	rax, 20
	or	rbx, rax
	shr	rcx, 44



	; carry <- limb1 = carry + state0*r1 + state1*r0 + 20*state2*r2
	movq	rax, KeyR1
	mul	state0
	add	rbx, rax
	adc	rcx, rdx

	movq	rax, KeyR0
	mul	state1
	add	rbx, rax
	adc	rcx, rdx

	movq	rax, Key20R2
	mul	state2


	add	rbx, rax
	adc	rcx, rdx

	; store lower 44 bit of limb1 onto stack
	mov	rax, rbx
	and	rax, mask
	push	rax

	; carry >>= 44
	shr	rbx, 44
	mov	rax, rcx
	shl	rax, 20
	or	rbx, rax
	shr	rcx, 44


	; carry <- limb2 = carry + state0*r2 + state1*r1 + state2*r0
	movq	rax, KeyR2
	mul	state0
	add	rbx, rax
	adc	rcx, rdx

	movq	rax, KeyR1
	mul	state1
	add	rbx, rax
	adc	rcx, rdx

	movq	rax, KeyR0
	mul	state2
	add	rbx, rax
	adc	rcx, rdx

	; state2 <- lower 42 bits of carry
	mov	state2, rbx
	mov	rax, mask
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
%endmacro





section	.text


;; Input:
;;	RDI	context
;;	RSI	r
;;	RDX	s
;;
	align	16
	global	poly1305_init
poly1305_init:
	cld

	; copy secret
	movdqu	xmm0, [rdx]
	movdqu	[rdi + context.secret], xmm0


	mov	mask, 0xfffffffffff

	; rax <- clamped lower 64 bit of r
	lodsq
	mov	rcx, 0x0ffffffc0fffffff
	and	rax, rcx

	; context.KeyR0 <- bits [0,44) of r
	mov	rdx, rax
	and	rdx, mask
	mov	[rdi + context.KeyR0], rdx

	; rdx <- unused 20 bits of lower part of r
	mov	rdx, rax
	shr	rdx, 44


	; rax <- clamped upper 64 bits of r
	lodsq
	;mov	rcx, 0x0ffffffc0ffffffc
	sub	rcx, 3
	and	rax, rcx

	; context.KeyR1 <- bits [44,88) of r
	mov	rcx, rax
	shl	rcx, 20
	or	rdx, rcx
	and	rdx, mask
	mov	[rdi + context.KeyR1], rdx

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
	shl	rdx, 2
	mov	rax, rdx
	shl	rdx, 2
	add	rax, rdx
	mov	[rdi + context.Key20R1], rax


	; context.status <- 0
	xor	rax, rax
	mov	[rdi + context.state0], rax
	mov	[rdi + context.state1], rax
	mov	[rdi + context.state2], rax

	; context.fill <- 0
	mov	[rdi + context.fill], al
	ret


;; Input:
;;	RDI	ctx
;;	RSI	data
;;	RDX	len
;;

	align	16
	global	poly1305_update
poly1305_update:
	push	rbp
	push	rbx
	push	r12

	cld

	; rbp <- context address
	mov	rbp, rdi

	; r12 <- data length
	mov	r12, rdx

	; load state
	mov	state0, [rbp + context.state0]
	mov	state1, [rbp + context.state1]
	mov	state2, [rbp + context.state2]

	; load key
	movq	KeyR0, [rbp + context.KeyR0]
	movq	KeyR1, [rbp + context.KeyR1]
	movq	KeyR2, [rbp + context.KeyR2]
	movq	Key20R1, [rbp + context.Key20R1]
	movq	Key20R2, [rbp + context.Key20R2]

	; mask <- 44bit mask
	mov	mask, 0xfffffffffff


	; do we have data in internal buffer?
	movzx	rcx, byte [rbp + context.fill]
	or	cl, cl
	je	.reload_data

	;
	; fill up internal buffer
	;

	; rdi <- current buffer position
	lea	rdi, [rdi + context.buffer + rcx]

	; rcx <- needed bytes = 16 - rcx
	neg	rcx
	add	rcx, 16

	; we need rcx bytes, do we have that much?
	cmp	rcx, r12
	jbe	.fillup

	; copy what we have and go home...
	mov	rcx, r12
	add	[rbp + context.fill], cl
	rep	movsb
	jmp	.return


.fillup:
	sub	r12, rcx
	rep	movsb

	;
	; add data from internal buffer to state
	;
	mov	rax, [rbp + context.buffer]
	mov	rbx, rax
	and	rax, mask
	add	state0, rax

	mov	rax, [rbp + context.buffer + 8]
	mov	rcx, rax
	shl	rax, 20
	shr	rbx, 44
	or	rax, rbx
	and	rax, mask
	add	state1, rax

	shr	rcx, 24
	add	state2, rcx

	align	16
.mulr:
	; add 2^128 padding to state
	mov	rcx, 0x10000000000
	add	state2, rcx

	; multiplicate with secret r
	mulr

.reload_data:
	cmp	r12, 16
	jb	.done

	prefetchnta	[rsi+128]
	
	; load next data
	movdqu	xmm0, [rsi]
	add	rsi, 16

	movq	rax, xmm0
	psrldq	xmm0, 5
	movq	rbx, xmm0
	psrldq	xmm0, 6
	movq	rcx, xmm0

	shr	rbx, 4
	and	rax, mask
	and	rbx, mask

	; add to state
	add	state0, rax
	add	state1, rbx
	add	state2, rcx

	sub	r12, 16
	jmp	.mulr


.done:
	; write state to context
	mov	[rbp + context.state0], state0
	mov	[rbp + context.state1], state1
	mov	[rbp + context.state2], state2

	; save remaining data to internal buffer
	lea	rdi, [rbp + context.buffer]
	mov	rcx, r12
	mov	[rbp + context.fill], cl
	rep	movsb

.return:
	pop	r12
	pop	rbx
	pop	rbp
	ret

;
; carry_reduce - performs one carry-reduce round for state
;
; assumes:
;	mask = 2^45-1 = 0xfffffffffff
;	rcx = 2^43-1 = 0x3ffffffffff
;
%macro carry_reduce	0
	mov	rax, state0
	shr	rax, 44
	and	state0, mask

	add	state1, rax
	mov	rax, state1
	shr	rax, 44
	and	state1, mask

	add	state2, rax
	mov	rax, state2
	shr	rax, 42
	and	state2, rcx

	; state0 += 5*rax
	add	state0, rax
	shl	rax, 2
	add	state0, rax
%endmacro




;; Input:
;;	RDI	context
;;	RSI	mac
;;
	align	16
	global	poly1305_mac
poly1305_mac:
	push	rbp
	cld

	; rbp <- context address
	mov	rbp, rdi

	; load state
	mov	state0, [rbp + context.state0]
	mov	state1, [rbp + context.state1]
	mov	state2, [rbp + context.state2]

	; 44bit mask
	mov	mask, 0xfffffffffff


	; do we have data left in internal buffer?
	movzx	rcx, byte [rbp + context.fill]
	or	rcx, rcx
	jz	.finalize

	;
	; handle internal buffer
	;
	push	rbx
	push	rdx


	; rdi <- end of data in internal buffer
	lea	rdi, [rbp + context.buffer + rcx]

	; add padding
	mov	byte [rdi], 1
	inc	rdi

	; rcx <- unused bytes in buffer = 16 - rcx - 1
	neg	rcx
	add	rcx, 15

	; zero unsed buffer space
	xor	al, al
	rep	stosb


	; add data from internal buffer to state
	mov	rax, [rbp + context.buffer]
	mov	rbx, rax
	and	rax, mask
	add	state0, rax

	mov	rax, [rbp + context.buffer + 8]
	mov	rcx, rax
	shl	rax, 20
	shr	rbx, 44
	or	rax, rbx
	and	rax, mask
	add	state1, rax

	shr	rcx, 24
	add	state2, rcx

	; load key
	movq	KeyR0, [rbp + context.KeyR0]
	movq	KeyR1, [rbp + context.KeyR1]
	movq	KeyR2, [rbp + context.KeyR2]
	movq	Key20R1, [rbp + context.Key20R1]
	movq	Key20R2, [rbp + context.Key20R2]

	mulr

	pop	rdx
	pop	rbx


.finalize:
	;
	; completly reduce state
	;
	mov	rcx, mask
	shr	rcx, 2

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
	add	state0, qword [rbp + context.secret]
	adc	state1, qword [rbp + context.secret + 8]

	;
	; export final poly1305 mac
	;
	mov	[rsi], state0
	mov	[rsi + 8], state1

	pop	rbp
	ret
