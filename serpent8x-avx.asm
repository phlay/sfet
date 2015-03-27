;;
;; x86_64 AVX implementation of serpent cipher with counter mode.
;;
;; Written by Philipp Lay <philipp.lay@illunis.net>
;;
;; The S-Boxes are due to Brian Gladman and Sam Simpson with a little
;; hand tuning by me.
;;
;; The clever trick to unconditional increment the counter (see ctr_inc
;; and serpent8x_ctr) cames from the linux kernel (glue_helper-asm-avx.S) 
;; and is due to Jussi Kivilinna <jussi.kivilinna@iki.fi>.
;;
;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.
;;


%define RA	xmm0
%define RB	xmm1
%define RC	xmm2
%define RD	xmm3

%define RE	xmm4
%define RF	xmm5
%define RG	xmm6
%define RH	xmm7

%define RI	xmm8
%define RJ	xmm9
%define RK	xmm10
%define RL	xmm11

%define TA	xmm12
%define TB	xmm13
%define TC	xmm14
%define TD	xmm15

%define RKEY	RDX



%macro load8	9
	vmovdqu		%1, [%9 + 16*0]
	vmovdqu		%2, [%9 + 16*1]
	vmovdqu		%3, [%9 + 16*2]
	vmovdqu		%4, [%9 + 16*3]
	vmovdqu		%5, [%9 + 16*4]
	vmovdqu		%6, [%9 + 16*5]
	vmovdqu		%7, [%9 + 16*6]
	vmovdqu		%8, [%9 + 16*7]
%endmacro

%macro store8	9
	vmovdqu		[%9 + 16*0], %1
	vmovdqu		[%9 + 16*1], %2
	vmovdqu		[%9 + 16*2], %3
	vmovdqu		[%9 + 16*3], %4
	vmovdqu		[%9 + 16*4], %5
	vmovdqu		[%9 + 16*5], %6
	vmovdqu		[%9 + 16*6], %7
	vmovdqu		[%9 + 16*7], %8
%endmacro


%macro rol128	3
	vpslld		TA, %2, %3
	vpsrld		%1, %2, 32 - %3
	vpor		%1, %1, TA
%endmacro

%macro transpose	8
	vpunpckldq	TA, %5, %6
	vpunpckhdq	TB, %5, %6
	vpunpckldq	TC, %7, %8
	vpunpckhdq	%4, %7, %8

	vpunpcklqdq	%1, TA, TC
	vpunpckhqdq	%2, TA, TC
	vpunpcklqdq	%3, TB, %4
	vpunpckhqdq	%4, TB, %4
%endmacro


%macro ltrans	4
	; %1 <- %1 <<< 13
	rol128	%1, %1, 13

	; %3 <- %3 <<< 3
	rol128	%3, %3, 3

	; %2 <- %2 xor %1 xor %3
	vpxor	%2, %2, %1
	vpxor	%2, %2, %3

	; %2 <- %2 <<< 1
	rol128	%2, %2, 1

	; %4 <- %4 xor %3 xor (%1 << 3)
	vpslld	TA, %1, 3
	vpxor	%4, %4, %3
	vpxor	%4, %4, TA

	; %4 <- %4 <<< 7
	rol128	%4, %4, 7

	; %1 <- %1 xor %2 xor %4
	vpxor	%1, %1, %2
	vpxor	%1, %1, %4

	; %3 <- %3 xor %4 xor (%2 << 7)
	vpslld	TA, %2, 7
	vpxor	%3, %3, %4
	vpxor	%3, %3, TA

	; %1 <- %1 <<< 5
	rol128	%1, %1, 5

	; %3 <- %3 <<< 22
	rol128	%3, %3, 22
%endmacro



%macro	S0	8
	vpand	%4, %5, %8
	vpxor	%1, %5, %8
	vpxor	%2, %7, %1
	vpxor	%3, %6, %2
	vpxor	%4, %4, %3
	vpand	%1, %1, %6
	vpxor	%1, %1, %5
	vpor	%5, %7, %1
	vpxor	%3, %3, %5
	vpxor	%5, %2, %1
	vpand	%5, %5, %4
	vpxor	%2, %2, TD
	vpxor	%2, %2, %5
	vpxor	%1, %1, TD
	vpxor	%1, %1, %5
%endmacro

%macro	S1	8
	vpxor	%1, %5, TD
	vpxor	%1, %1, %6
	vpor	%5, %5, %1
	vpxor	%5, %5, %7
	vpxor	%3, %8, %5
	vpor	%8, %8, %1
	vpxor	%6, %6, %8
	vpxor	%1, %1, %3
	vpand	%2, %5, %6
	vpxor	%4, %1, %2
	vpxor	%6, %6, %5
	vpxor	%2, %4, %6
	vpand	%6, %6, %1
	vpxor	%1, %5, %6
%endmacro

%macro	S2	8
	vpxor	%2, %5, TD
	vpxor	TA, %6, %8
	vpand	%1, %7, %2
	vpxor	%1, %1, TA
	vpxor	%3, %7, %2
	vpxor	%7, %7, %1
	vpand	%7, %7, %6
	vpxor	%4, %3, %7
	vpor	%6, %8, %7
	vpor	%3, %3, %1
	vpand	%3, %3, %6
	vpxor	%3, %3, %5
	vpor	%6, %8, %2
	vpxor	%5, TA, %4
	vpxor	%2, %3, %6
	vpxor	%2, %2, %5
%endmacro

%macro	S3	8
	vpxor	%4, %7, %8
	vpand	%2, %5, %7
	vpor	%7, %5, %8
	vpxor	%5, %5, %6
	vpand	%1, %5, %7
	vpor	%2, %2, %1
	vpxor	%3, %4, %2
	vpxor	%7, %7, %6
	vpxor	%2, %2, %7
	vpand	%1, %4, %2
	vpxor	%1, %1, %5
	vpand	%7, %3, %1
	vpxor	%2, %2, %7
	vpor	%6, %6, %8
	vpxor	%4, %4, %7
	vpxor	%4, %4, %6
%endmacro

%macro	S4	8
	vpxor	%2, %5, %8
	vpand	%8, %8, %2
	vpxor	%8, %8, %7
	vpor	%7, %6, %8
	vpxor	%4, %2, %7
	vpxor	%6, %6, TD
	vpor	%1, %2, %6
	vpxor	%1, %1, %8
	vpxor	%6, %6, %2
	vpand	%2, %5, %1
	vpand	%3, %7, %6
	vpxor	%3, %3, %2
	vpand	%6, %6, %3
	vpxor	%8, %8, %5
	vpxor	%2, %6, %8
%endmacro

%macro	S5	8
	vpxor	%3, %5, %6
	vpxor	%4, %5, %8
	vpxor	%5, %5, TD
	vpxor	%1, %5, %7
	vpor	%7, %3, %4
	vpxor	%1, %1, %7
	vpand	%7, %8, %1
	vpxor	%6, %6, %7
	vpxor	%2, %3, %1
	vpor	%8, %5, %1
	vpxor	%2, %2, %7
	vpxor	%4, %4, %8
	vpor	%8, %3, %7
	vpxor	%3, %8, %4
	vpand	%4, %4, %2
	vpxor	%4, %4, %6
%endmacro

%macro	S6	8
	vpxor	%3, %5, %8
	vpxor	%5, %5, TD
	vpxor	%4, %6, %3
	vpor	%5, %5, %3
	vpxor	%5, %5, %7
	vpxor	%2, %5, %6
	vpor	%7, %3, %2
	vpxor	%7, %7, %8
	vpand	%8, %5, %7
	vpxor	%3, %4, %8
	vpxor	%6, %5, %7
	vpxor	%1, %3, %6
	vpxor	%5, %5, TD
	vpand	%4, %4, %6
	vpxor	%4, %4, %5
%endmacro

%macro	S7	8
	vpxor	%1, %6, %7
	vpand	%7, %7, %1
	vpxor	%7, %7, %8
	vpor	%2, %8, %1
	vpxor	%8, %5, %7
	vpand	%2, %2, %8
	vpxor	%2, %2, %6
	vpor	%6, %7, %2
	vpand	%4, %5, %8
	vpxor	%4, %4, %1
	vpxor	%6, %6, %8
	vpand	%3, %4, %6
	vpxor	%3, %3, %7
	vpxor	%5, %6, TD
	vpand	%1, %3, %4
	vpxor	%1, %1, %5
%endmacro


;; add round key and get block-sets in place again
;;
%macro add_round_key	0
	vbroadcastss	TA, [RKEY + 4*0]
	vpxor	RE, RA, TA
	vpxor	RA, RI, TA
	vbroadcastss	TA, [RKEY + 4*1]
	vpxor	RF, RB, TA
	vpxor	RB, RJ, TA
	vbroadcastss	TA, [RKEY + 4*2]
	vpxor	RG, RC, TA
	vpxor	RC, RK, TA
	vbroadcastss	TA, [RKEY + 4*3]
	vpxor	RH, RD, TA
	vpxor	RD, RL, TA

	add	RKEY, 16
%endmacro



;; round <sbox>
;;
%macro serpent_round	1
	; apply s-box to first block-set
	S%1	RI, RJ, RK, RL, RA, RB, RC, RD
	ltrans	RI, RJ, RK, RL

	; apply s-box to second block-set
	S%1	RA, RB, RC, RD, RE, RF, RG, RH
	ltrans	RA, RB, RC, RD

	add_round_key
%endmacro



%macro ctr_inc	2
	vpcmpeqq	TA, %2, TD
	vpsubq		%1, %2, TD
	vpslldq		TA, TA, 8
	vpsubq		%1, %1, TA
%endmacro


section .data

	align	16

endian_perm_vector:
	db 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0



section	.text


;; serpent8x - interweave two 4-way-serpents together
;;
;; Input:
;;	RDX	expkey
;;	block 1 to 8 in RA to RH

serpent8x:
	vpcmpeqd	TD, TD, TD

	transpose	RI, RJ, RK, RL, RA, RB, RC, RD
	transpose	RA, RB, RC, RD, RE, RF, RG, RH

	add_round_key

	mov		ECX, 3
.loop:
	serpent_round	0
	serpent_round	1
	serpent_round	2
	serpent_round	3
	serpent_round	4
	serpent_round	5
	serpent_round	6
	serpent_round	7
	dec		ECX
	jnz		.loop

	serpent_round	0
	serpent_round	1
	serpent_round	2
	serpent_round	3
	serpent_round	4
	serpent_round	5
	serpent_round	6

	; last round without linear transformation
	S7		RI, RJ, RK, RL, RA, RB, RC, RD
	S7		RA, RB, RC, RD, RE, RF, RG, RH
	add_round_key

	transpose	RA, RB, RC, RD, RA, RB, RC, RD
	transpose	RE, RF, RG, RH, RE, RF, RG, RH

	ret




;; serpent8x_ctr
;;
;; Input:
;;	RDI	dst
;;	RSI	src
;;	RDX	expkey
;;	RCX	counter

	global	serpent8x_ctr
serpent8x_ctr:
	; TD <- 2^64 - 1
	vpcmpeqd	TD, TD, TD
	vpsrldq		TD, TD, 8

	; TB <- permutation vector for little vs big endian conversion
	vmovdqa		TB, [endian_perm_vector]

	; load counter and convert it to little endian
	vmovdqu		RA, [RCX]
	vpshufb		RA, RA, TB

	; increment counters in little-endian
	ctr_inc		RB, RA
	ctr_inc		RC, RB
	ctr_inc		RD, RC
	ctr_inc		RE, RD
	ctr_inc		RF, RE
	ctr_inc		RG, RF
	ctr_inc		RH, RG
	ctr_inc		RI, RH

	; convert back to big-endian
	vpshufb		RA, RA, TB
	vpshufb		RB, RB, TB
	vpshufb		RC, RC, TB
	vpshufb		RD, RD, TB
	vpshufb		RE, RE, TB
	vpshufb		RF, RF, TB
	vpshufb		RG, RG, TB
	vpshufb		RH, RH, TB
	vpshufb		RI, RI, TB

	; store next counter back
	vmovdqu		[RCX], RI

	; encrypt counters
	call		serpent8x

	; encrypt blocks
	load8		RI, RJ, RK, RL, TA, TB, TC, TD, RSI
	vpxor		RI, RI, RA
	vpxor		RJ, RJ, RB
	vpxor		RK, RK, RC
	vpxor		RL, RL, RD
	vpxor		TA, TA, RE
	vpxor		TB, TB, RF
	vpxor		TC, TC, RG
	vpxor		TD, TD, RH
	store8		RI, RJ, RK, RL, TA, TB, TC, TD, RDI

	ret

%ifdef SELFTEST
;; serpent8x_encrypt - ecb encrypt 8 blocks in parallel (only used in selftest)
;;
;; Input:
;;      RDI     dst
;;      RSI     src
;;      RDX     expkey
;;
        global  serpent8x_encrypt
serpent8x_encrypt:
        load8   RA, RB, RC, RD, RE, RF, RG, RH, RSI
        call    serpent8x
        store8  RA, RB, RC, RD, RE, RF, RG, RH, RDI
        ret

%endif
