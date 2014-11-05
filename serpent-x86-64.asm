;;
;; x86-64 assembly version of serpent
;;
;; This code is based on serpent.c which was written by Dag Arne Osvik
;; for the linux kernel.
;;
;; Written by Philipp Lay <philipp.lay@illunis.net>
;;
;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.


%define RA	EAX
%define RB	R8D
%define RC	ECX
%define RD	R9D
%define RE	R10D

%define TMP	R11D
%define RK	RDX



%macro add_key	5
	mov	TMP, [RK + 4*(4*%5 + 0)]
	xor	%1, TMP
	mov	TMP, [RK + 4*(4*%5 + 1)]
	xor	%2, TMP
	mov	TMP, [RK + 4*(4*%5 + 2)]
	xor	%3, TMP
	mov	TMP, [RK + 4*(4*%5 + 3)]
	xor	%4, TMP
%endmacro


%macro ltrans	4
	; %1 <- %1 <<< 13
	rol	%1, 13

	; %3 <- %3 <<< 3
	rol	%3, 3

	; %2 <- %2 xor %1 xor %3
	xor	%2, %1
	xor	%2, %3

	; %4 <- %4 xor %3 xor (%1 << 3)
	mov	TMP, %1
	shl	TMP, 3
	xor	%4, %3
	xor	%4, TMP

	; %2 <- %2 <<< 1
	rol	%2, 1

	; %4 <- %4 <<< 7
	rol	%4, 7

	; %1 <- %1 xor %2 xor %4
	xor	%1, %2
	xor	%1, %4

	; %3 <- %3 xor %4 xor (%2 << 7)
	mov	TMP, %2
	shl	TMP, 7
	xor	%3, %4
	xor	%3, TMP

	; %1 <- %1 <<< 5
	rol	%1, 5

	; %3 <- %3 <<< 22
	rol	%3, 22
%endmacro


%macro S0	5
	mov	%5, %4
	or	%4, %1
	xor	%1, %5
	xor	%5, %3
	not	%5
	xor	%4, %2
	and	%2, %1
	xor	%2, %5
	xor	%3, %1
	xor	%1, %4
	or	%5, %1
	xor	%1, %3
	and	%3, %2
	xor	%4, %3
	not	%2
	xor	%3, %5
	xor	%2, %3
%endmacro

%macro S1	5
	mov	%5, %2
	xor	%2, %1
	xor	%1, %4
	not	%4
	and	%5, %2
	or	%1, %2
	xor	%4, %3
	xor	%1, %4
	xor	%2, %4
	xor	%4, %5
	or	%2, %5
	xor	%5, %3
	and	%3, %1
	xor	%3, %2
	or	%2, %1
	not	%1
	xor	%1, %3
	xor	%5, %2
%endmacro

%macro S2	5
	not	%4
	xor	%2, %1
	mov	%5, %1
	and	%1, %3
	xor	%1, %4
	or	%4, %5
	xor	%3, %2
	xor	%4, %2
	and	%2, %1
	xor	%1, %3
	and	%3, %4
	or	%4, %2
	not	%1
	xor	%4, %1
	xor	%5, %1
	xor	%1, %3
	or	%2, %3
%endmacro

%macro S3	5
	mov	%5, %2
	xor	%2, %4
	or	%4, %1
	and	%5, %1
	xor	%1, %3
	xor	%3, %2
	and	%2, %4
	xor	%3, %4
	or	%1, %5
	xor	%5, %4
	xor	%2, %1
	and	%1, %4
	and	%4, %5
	xor	%4, %3
	or	%5, %2
	and	%3, %2
	xor	%5, %4
	xor	%1, %4
	xor	%4, %3
%endmacro

%macro S4	5
	mov	%5, %4
	and	%4, %1
	xor	%1, %5
	xor	%4, %3
	or	%3, %5
	xor	%1, %2
	xor	%5, %4
	or	%3, %1
	xor	%3, %2
	and	%2, %1
	xor	%2, %5
	and	%5, %3
	xor	%3, %4
	xor	%5, %1
	or	%4, %2
	not	%2
	xor	%4, %1
%endmacro

%macro S5	5
	mov	%5, %2
	or	%2, %1
	xor	%3, %2
	not	%4
	xor	%5, %1
	xor	%1, %3
	and	%2, %5
	or	%5, %4
	xor	%5, %1
	and	%1, %4
	xor	%2, %4
	xor	%4, %3
	xor	%1, %2
	and	%3, %5
	xor	%2, %3
	and	%3, %1
	xor	%4, %3
%endmacro


%macro S6	5
	mov	%5, %2
	xor	%4, %1
	xor	%2, %3
	xor	%3, %1
	and	%1, %4
	or	%2, %4
	not	%5
	xor	%1, %2
	xor	%2, %3
	xor	%4, %5
	xor	%5, %1
	and	%3, %1
	xor	%5, %2
	xor	%3, %4
	and	%4, %2
	xor	%4, %1
	xor	%2, %3
%endmacro

%macro S7	5
	not	%2
	mov	%5, %2
	not	%1
	and	%2, %3
	xor	%2, %4
	or	%4, %5
	xor	%5, %3
	xor	%3, %4
	xor	%4, %1
	or	%1, %2
	and	%3, %1
	xor	%1, %5
	xor	%5, %4
	and	%4, %1
	xor	%5, %2
	xor	%3, %5
	xor	%4, %2
	or	%5, %1
	xor	%5, %2
%endmacro

%macro round	6
%assign i (%6 % 8)
	ltrans		%1, %2, %3, %4
	add_key		%1, %2, %3, %4, %6
	S%[i]		%1, %2, %3, %4, %5
%endmacro


section	.text



;; serpent_encrypt
;;
;; Input:
;;	RDI	dst
;;	RSI	src
;;	RDX	expkey

	global	serpent_encrypt
serpent_encrypt:
	mov		RA, [RSI +  0]
	mov		RB, [RSI +  4]
	mov		RC, [RSI +  8]
	mov		RD, [RSI + 12]

	add_key		RA, RB, RC, RD, 0
	S0		RA, RB, RC, RD, RE
	round		RC, RB, RD, RA, RE, 1
	round		RE, RD, RA, RC, RB, 2
	round		RB, RD, RE, RC, RA, 3
	round		RC, RA, RD, RB, RE, 4
	round		RA, RD, RB, RE, RC, 5
	round		RC, RA, RD, RE, RB, 6
	round		RD, RB, RA, RE, RC, 7
	round		RC, RA, RE, RD, RB, 8
	round		RE, RA, RD, RC, RB, 9
	round		RB, RD, RC, RE, RA, 10
	round		RA, RD, RB, RE, RC, 11
	round		RE, RC, RD, RA, RB, 12
	round		RC, RD, RA, RB, RE, 13
	round		RE, RC, RD, RB, RA, 14
	round		RD, RA, RC, RB, RE, 15
	round		RE, RC, RB, RD, RA, 16
	round		RB, RC, RD, RE, RA, 17
	round		RA, RD, RE, RB, RC, 18
	round		RC, RD, RA, RB, RE, 19
	round		RB, RE, RD, RC, RA, 20
	round		RE, RD, RC, RA, RB, 21
	round		RB, RE, RD, RA, RC, 22
	round		RD, RC, RE, RA, RB, 23
	round		RB, RE, RA, RD, RC, 24
	round		RA, RE, RD, RB, RC, 25
	round		RC, RD, RB, RA, RE, 26
	round		RE, RD, RC, RA, RB, 27
	round		RA, RB, RD, RE, RC, 28
	round		RB, RD, RE, RC, RA, 29
	round		RA, RB, RD, RC, RE, 30
	round		RD, RE, RB, RC, RA, 31
	add_key		RA, RB, RC, RD, 32

	mov		[RDI +  0], RA
	mov		[RDI +  4], RB
	mov		[RDI +  8], RC
	mov		[RDI + 12], RD

	ret
