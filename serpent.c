/*
 * Serpent Cipher Algorithm (encryption only).
 *
 * This code was originally written for the Linux Kernel by Dag Arne Osvik and
 * only slightly modified for this project (i.e. decryption removed and kernel
 * dependencies removed).
 *
 * Copyright (C) 2002 Dag Arne Osvik <osvik@ii.uib.no>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <endian.h>
#include <stdint.h>
#include <string.h>

#include "serpent.h"


#define PHI 0x9e3779b9UL
#define ROL(x,r) ((x) = ((x) << (r)) | ((x) >> (32-(r))))
#define ROR(x,r) ((x) = ((x) >> (r)) | ((x) << (32-(r))))

#define keyiter(a,b,c,d,i,j) \
        b ^= d; b ^= c; b ^= a; b ^= PHI ^ i; ROL(b,11); k[j] = b;

#define loadkeys(x0,x1,x2,x3,i) \
	x0=k[i]; x1=k[i+1]; x2=k[i+2]; x3=k[i+3];

#define storekeys(x0,x1,x2,x3,i) \
	k[i]=x0; k[i+1]=x1; k[i+2]=x2; k[i+3]=x3;

#define K(x0,x1,x2,x3,i)				\
	x3 ^= k[4*(i)+3];        x2 ^= k[4*(i)+2];	\
	x1 ^= k[4*(i)+1];        x0 ^= k[4*(i)+0];

#define LK(x0,x1,x2,x3,x4,i)				\
					ROL(x0,13);	\
	ROL(x2,3);	x1 ^= x0;	x4  = x0 << 3;	\
	x3 ^= x2;	x1 ^= x2;			\
	ROL(x1,1);	x3 ^= x4;			\
	ROL(x3,7);	x4  = x1;			\
	x0 ^= x1;	x4 <<= 7;	x2 ^= x3;	\
	x0 ^= x3;	x2 ^= x4;	x3 ^= k[4*i+3];	\
	x1 ^= k[4*i+1];	ROL(x0,5);	ROL(x2,22);	\
	x0 ^= k[4*i+0];	x2 ^= k[4*i+2];

#define S0(x0,x1,x2,x3,x4)				\
					x4  = x3;	\
	x3 |= x0;	x0 ^= x4;	x4 ^= x2;	\
	x4 =~ x4;	x3 ^= x1;	x1 &= x0;	\
	x1 ^= x4;	x2 ^= x0;	x0 ^= x3;	\
	x4 |= x0;	x0 ^= x2;	x2 &= x1;	\
	x3 ^= x2;	x1 =~ x1;	x2 ^= x4;	\
	x1 ^= x2;

#define S1(x0,x1,x2,x3,x4)				\
					x4  = x1;	\
	x1 ^= x0;	x0 ^= x3;	x3 =~ x3;	\
	x4 &= x1;	x0 |= x1;	x3 ^= x2;	\
	x0 ^= x3;	x1 ^= x3;	x3 ^= x4;	\
	x1 |= x4;	x4 ^= x2;	x2 &= x0;	\
	x2 ^= x1;	x1 |= x0;	x0 =~ x0;	\
	x0 ^= x2;	x4 ^= x1;

#define S2(x0,x1,x2,x3,x4)				\
					x3 =~ x3;	\
	x1 ^= x0;	x4  = x0;	x0 &= x2;	\
	x0 ^= x3;	x3 |= x4;	x2 ^= x1;	\
	x3 ^= x1;	x1 &= x0;	x0 ^= x2;	\
	x2 &= x3;	x3 |= x1;	x0 =~ x0;	\
	x3 ^= x0;	x4 ^= x0;	x0 ^= x2;	\
	x1 |= x2;

#define S3(x0,x1,x2,x3,x4)				\
					x4  = x1;	\
	x1 ^= x3;	x3 |= x0;	x4 &= x0;	\
	x0 ^= x2;	x2 ^= x1;	x1 &= x3;	\
	x2 ^= x3;	x0 |= x4;	x4 ^= x3;	\
	x1 ^= x0;	x0 &= x3;	x3 &= x4;	\
	x3 ^= x2;	x4 |= x1;	x2 &= x1;	\
	x4 ^= x3;	x0 ^= x3;	x3 ^= x2;

#define S4(x0,x1,x2,x3,x4)				\
					x4  = x3;	\
	x3 &= x0;	x0 ^= x4;			\
	x3 ^= x2;	x2 |= x4;	x0 ^= x1;	\
	x4 ^= x3;	x2 |= x0;			\
	x2 ^= x1;	x1 &= x0;			\
	x1 ^= x4;	x4 &= x2;	x2 ^= x3;	\
	x4 ^= x0;	x3 |= x1;	x1 =~ x1;	\
	x3 ^= x0;

#define S5(x0,x1,x2,x3,x4)				\
	x4  = x1;	x1 |= x0;			\
	x2 ^= x1;	x3 =~ x3;	x4 ^= x0;	\
	x0 ^= x2;	x1 &= x4;	x4 |= x3;	\
	x4 ^= x0;	x0 &= x3;	x1 ^= x3;	\
	x3 ^= x2;	x0 ^= x1;	x2 &= x4;	\
	x1 ^= x2;	x2 &= x0;			\
	x3 ^= x2;

#define S6(x0,x1,x2,x3,x4)				\
					x4  = x1;	\
	x3 ^= x0;	x1 ^= x2;	x2 ^= x0;	\
	x0 &= x3;	x1 |= x3;	x4 =~ x4;	\
	x0 ^= x1;	x1 ^= x2;			\
	x3 ^= x4;	x4 ^= x0;	x2 &= x0;	\
	x4 ^= x1;	x2 ^= x3;	x3 &= x1;	\
	x3 ^= x0;	x1 ^= x2;

#define S7(x0,x1,x2,x3,x4)				\
					x1 =~ x1;	\
	x4  = x1;	x0 =~ x0;	x1 &= x2;	\
	x1 ^= x3;	x3 |= x4;	x4 ^= x2;	\
	x2 ^= x3;	x3 ^= x0;	x0 |= x1;	\
	x2 &= x0;	x0 ^= x4;	x4 ^= x3;	\
	x3 &= x0;	x4 ^= x1;			\
	x2 ^= x4;	x3 ^= x1;	x4 |= x0;	\
	x4 ^= x1;


int
serpent_setkey(uint32_t *expkey, const uint8_t *key, unsigned int keylen)
{
	uint32_t	*k = expkey;
	uint8_t		*k8 = (uint8_t *)expkey;
	uint32_t	 r0,r1,r2,r3,r4;
	int		 i;

	if (keylen < SERPENT_MIN_KEY_SIZE || keylen > SERPENT_MAX_KEY_SIZE)
		return -1;

	/* Copy key, add padding */
	for (i = 0; i < keylen; ++i)
		k8[i] = key[i];
	if (i < SERPENT_MAX_KEY_SIZE)
		k8[i++] = 1;
	while (i < SERPENT_MAX_KEY_SIZE)
		k8[i++] = 0;

	/* Expand key using polynomial */
	r0 = le32toh(k[3]);
	r1 = le32toh(k[4]);
	r2 = le32toh(k[5]);
	r3 = le32toh(k[6]);
	r4 = le32toh(k[7]);

	keyiter(le32toh(k[0]),r0,r4,r2,0,0);
	keyiter(le32toh(k[1]),r1,r0,r3,1,1);
	keyiter(le32toh(k[2]),r2,r1,r4,2,2);
	keyiter(le32toh(k[3]),r3,r2,r0,3,3);
	keyiter(le32toh(k[4]),r4,r3,r1,4,4);
	keyiter(le32toh(k[5]),r0,r4,r2,5,5);
	keyiter(le32toh(k[6]),r1,r0,r3,6,6);
	keyiter(le32toh(k[7]),r2,r1,r4,7,7);

	keyiter(k[  0],r3,r2,r0,  8,  8); keyiter(k[  1],r4,r3,r1,  9,  9);
	keyiter(k[  2],r0,r4,r2, 10, 10); keyiter(k[  3],r1,r0,r3, 11, 11);
	keyiter(k[  4],r2,r1,r4, 12, 12); keyiter(k[  5],r3,r2,r0, 13, 13);
	keyiter(k[  6],r4,r3,r1, 14, 14); keyiter(k[  7],r0,r4,r2, 15, 15);
	keyiter(k[  8],r1,r0,r3, 16, 16); keyiter(k[  9],r2,r1,r4, 17, 17);
	keyiter(k[ 10],r3,r2,r0, 18, 18); keyiter(k[ 11],r4,r3,r1, 19, 19);
	keyiter(k[ 12],r0,r4,r2, 20, 20); keyiter(k[ 13],r1,r0,r3, 21, 21);
	keyiter(k[ 14],r2,r1,r4, 22, 22); keyiter(k[ 15],r3,r2,r0, 23, 23);
	keyiter(k[ 16],r4,r3,r1, 24, 24); keyiter(k[ 17],r0,r4,r2, 25, 25);
	keyiter(k[ 18],r1,r0,r3, 26, 26); keyiter(k[ 19],r2,r1,r4, 27, 27);
	keyiter(k[ 20],r3,r2,r0, 28, 28); keyiter(k[ 21],r4,r3,r1, 29, 29);
	keyiter(k[ 22],r0,r4,r2, 30, 30); keyiter(k[ 23],r1,r0,r3, 31, 31);

	k += 50;

	keyiter(k[-26],r2,r1,r4, 32,-18); keyiter(k[-25],r3,r2,r0, 33,-17);
	keyiter(k[-24],r4,r3,r1, 34,-16); keyiter(k[-23],r0,r4,r2, 35,-15);
	keyiter(k[-22],r1,r0,r3, 36,-14); keyiter(k[-21],r2,r1,r4, 37,-13);
	keyiter(k[-20],r3,r2,r0, 38,-12); keyiter(k[-19],r4,r3,r1, 39,-11);
	keyiter(k[-18],r0,r4,r2, 40,-10); keyiter(k[-17],r1,r0,r3, 41, -9);
	keyiter(k[-16],r2,r1,r4, 42, -8); keyiter(k[-15],r3,r2,r0, 43, -7);
	keyiter(k[-14],r4,r3,r1, 44, -6); keyiter(k[-13],r0,r4,r2, 45, -5);
	keyiter(k[-12],r1,r0,r3, 46, -4); keyiter(k[-11],r2,r1,r4, 47, -3);
	keyiter(k[-10],r3,r2,r0, 48, -2); keyiter(k[ -9],r4,r3,r1, 49, -1);
	keyiter(k[ -8],r0,r4,r2, 50,  0); keyiter(k[ -7],r1,r0,r3, 51,  1);
	keyiter(k[ -6],r2,r1,r4, 52,  2); keyiter(k[ -5],r3,r2,r0, 53,  3);
	keyiter(k[ -4],r4,r3,r1, 54,  4); keyiter(k[ -3],r0,r4,r2, 55,  5);
	keyiter(k[ -2],r1,r0,r3, 56,  6); keyiter(k[ -1],r2,r1,r4, 57,  7);
	keyiter(k[  0],r3,r2,r0, 58,  8); keyiter(k[  1],r4,r3,r1, 59,  9);
	keyiter(k[  2],r0,r4,r2, 60, 10); keyiter(k[  3],r1,r0,r3, 61, 11);
	keyiter(k[  4],r2,r1,r4, 62, 12); keyiter(k[  5],r3,r2,r0, 63, 13);
	keyiter(k[  6],r4,r3,r1, 64, 14); keyiter(k[  7],r0,r4,r2, 65, 15);
	keyiter(k[  8],r1,r0,r3, 66, 16); keyiter(k[  9],r2,r1,r4, 67, 17);
	keyiter(k[ 10],r3,r2,r0, 68, 18); keyiter(k[ 11],r4,r3,r1, 69, 19);
	keyiter(k[ 12],r0,r4,r2, 70, 20); keyiter(k[ 13],r1,r0,r3, 71, 21);
	keyiter(k[ 14],r2,r1,r4, 72, 22); keyiter(k[ 15],r3,r2,r0, 73, 23);
	keyiter(k[ 16],r4,r3,r1, 74, 24); keyiter(k[ 17],r0,r4,r2, 75, 25);
	keyiter(k[ 18],r1,r0,r3, 76, 26); keyiter(k[ 19],r2,r1,r4, 77, 27);
	keyiter(k[ 20],r3,r2,r0, 78, 28); keyiter(k[ 21],r4,r3,r1, 79, 29);
	keyiter(k[ 22],r0,r4,r2, 80, 30); keyiter(k[ 23],r1,r0,r3, 81, 31);

	k += 50;

	keyiter(k[-26],r2,r1,r4, 82,-18); keyiter(k[-25],r3,r2,r0, 83,-17);
	keyiter(k[-24],r4,r3,r1, 84,-16); keyiter(k[-23],r0,r4,r2, 85,-15);
	keyiter(k[-22],r1,r0,r3, 86,-14); keyiter(k[-21],r2,r1,r4, 87,-13);
	keyiter(k[-20],r3,r2,r0, 88,-12); keyiter(k[-19],r4,r3,r1, 89,-11);
	keyiter(k[-18],r0,r4,r2, 90,-10); keyiter(k[-17],r1,r0,r3, 91, -9);
	keyiter(k[-16],r2,r1,r4, 92, -8); keyiter(k[-15],r3,r2,r0, 93, -7);
	keyiter(k[-14],r4,r3,r1, 94, -6); keyiter(k[-13],r0,r4,r2, 95, -5);
	keyiter(k[-12],r1,r0,r3, 96, -4); keyiter(k[-11],r2,r1,r4, 97, -3);
	keyiter(k[-10],r3,r2,r0, 98, -2); keyiter(k[ -9],r4,r3,r1, 99, -1);
	keyiter(k[ -8],r0,r4,r2,100,  0); keyiter(k[ -7],r1,r0,r3,101,  1);
	keyiter(k[ -6],r2,r1,r4,102,  2); keyiter(k[ -5],r3,r2,r0,103,  3);
	keyiter(k[ -4],r4,r3,r1,104,  4); keyiter(k[ -3],r0,r4,r2,105,  5);
	keyiter(k[ -2],r1,r0,r3,106,  6); keyiter(k[ -1],r2,r1,r4,107,  7);
	keyiter(k[  0],r3,r2,r0,108,  8); keyiter(k[  1],r4,r3,r1,109,  9);
	keyiter(k[  2],r0,r4,r2,110, 10); keyiter(k[  3],r1,r0,r3,111, 11);
	keyiter(k[  4],r2,r1,r4,112, 12); keyiter(k[  5],r3,r2,r0,113, 13);
	keyiter(k[  6],r4,r3,r1,114, 14); keyiter(k[  7],r0,r4,r2,115, 15);
	keyiter(k[  8],r1,r0,r3,116, 16); keyiter(k[  9],r2,r1,r4,117, 17);
	keyiter(k[ 10],r3,r2,r0,118, 18); keyiter(k[ 11],r4,r3,r1,119, 19);
	keyiter(k[ 12],r0,r4,r2,120, 20); keyiter(k[ 13],r1,r0,r3,121, 21);
	keyiter(k[ 14],r2,r1,r4,122, 22); keyiter(k[ 15],r3,r2,r0,123, 23);
	keyiter(k[ 16],r4,r3,r1,124, 24); keyiter(k[ 17],r0,r4,r2,125, 25);
	keyiter(k[ 18],r1,r0,r3,126, 26); keyiter(k[ 19],r2,r1,r4,127, 27);
	keyiter(k[ 20],r3,r2,r0,128, 28); keyiter(k[ 21],r4,r3,r1,129, 29);
	keyiter(k[ 22],r0,r4,r2,130, 30); keyiter(k[ 23],r1,r0,r3,131, 31);

	/* Apply S-boxes */

	S3(r3,r4,r0,r1,r2); storekeys(r1,r2,r4,r3, 28); loadkeys(r1,r2,r4,r3, 24);
	S4(r1,r2,r4,r3,r0); storekeys(r2,r4,r3,r0, 24); loadkeys(r2,r4,r3,r0, 20);
	S5(r2,r4,r3,r0,r1); storekeys(r1,r2,r4,r0, 20); loadkeys(r1,r2,r4,r0, 16);
	S6(r1,r2,r4,r0,r3); storekeys(r4,r3,r2,r0, 16); loadkeys(r4,r3,r2,r0, 12);
	S7(r4,r3,r2,r0,r1); storekeys(r1,r2,r0,r4, 12); loadkeys(r1,r2,r0,r4,  8);
	S0(r1,r2,r0,r4,r3); storekeys(r0,r2,r4,r1,  8); loadkeys(r0,r2,r4,r1,  4);
	S1(r0,r2,r4,r1,r3); storekeys(r3,r4,r1,r0,  4); loadkeys(r3,r4,r1,r0,  0);
	S2(r3,r4,r1,r0,r2); storekeys(r2,r4,r3,r0,  0); loadkeys(r2,r4,r3,r0, -4);
	S3(r2,r4,r3,r0,r1); storekeys(r0,r1,r4,r2, -4); loadkeys(r0,r1,r4,r2, -8);
	S4(r0,r1,r4,r2,r3); storekeys(r1,r4,r2,r3, -8); loadkeys(r1,r4,r2,r3,-12);
	S5(r1,r4,r2,r3,r0); storekeys(r0,r1,r4,r3,-12); loadkeys(r0,r1,r4,r3,-16);
	S6(r0,r1,r4,r3,r2); storekeys(r4,r2,r1,r3,-16); loadkeys(r4,r2,r1,r3,-20);
	S7(r4,r2,r1,r3,r0); storekeys(r0,r1,r3,r4,-20); loadkeys(r0,r1,r3,r4,-24);
	S0(r0,r1,r3,r4,r2); storekeys(r3,r1,r4,r0,-24); loadkeys(r3,r1,r4,r0,-28);
	k -= 50;
	S1(r3,r1,r4,r0,r2); storekeys(r2,r4,r0,r3, 22); loadkeys(r2,r4,r0,r3, 18);
	S2(r2,r4,r0,r3,r1); storekeys(r1,r4,r2,r3, 18); loadkeys(r1,r4,r2,r3, 14);
	S3(r1,r4,r2,r3,r0); storekeys(r3,r0,r4,r1, 14); loadkeys(r3,r0,r4,r1, 10);
	S4(r3,r0,r4,r1,r2); storekeys(r0,r4,r1,r2, 10); loadkeys(r0,r4,r1,r2,  6);
	S5(r0,r4,r1,r2,r3); storekeys(r3,r0,r4,r2,  6); loadkeys(r3,r0,r4,r2,  2);
	S6(r3,r0,r4,r2,r1); storekeys(r4,r1,r0,r2,  2); loadkeys(r4,r1,r0,r2, -2);
	S7(r4,r1,r0,r2,r3); storekeys(r3,r0,r2,r4, -2); loadkeys(r3,r0,r2,r4, -6);
	S0(r3,r0,r2,r4,r1); storekeys(r2,r0,r4,r3, -6); loadkeys(r2,r0,r4,r3,-10);
	S1(r2,r0,r4,r3,r1); storekeys(r1,r4,r3,r2,-10); loadkeys(r1,r4,r3,r2,-14);
	S2(r1,r4,r3,r2,r0); storekeys(r0,r4,r1,r2,-14); loadkeys(r0,r4,r1,r2,-18);
	S3(r0,r4,r1,r2,r3); storekeys(r2,r3,r4,r0,-18); loadkeys(r2,r3,r4,r0,-22);
	k -= 50;
	S4(r2,r3,r4,r0,r1); storekeys(r3,r4,r0,r1, 28); loadkeys(r3,r4,r0,r1, 24);
	S5(r3,r4,r0,r1,r2); storekeys(r2,r3,r4,r1, 24); loadkeys(r2,r3,r4,r1, 20);
	S6(r2,r3,r4,r1,r0); storekeys(r4,r0,r3,r1, 20); loadkeys(r4,r0,r3,r1, 16);
	S7(r4,r0,r3,r1,r2); storekeys(r2,r3,r1,r4, 16); loadkeys(r2,r3,r1,r4, 12);
	S0(r2,r3,r1,r4,r0); storekeys(r1,r3,r4,r2, 12); loadkeys(r1,r3,r4,r2,  8);
	S1(r1,r3,r4,r2,r0); storekeys(r0,r4,r2,r1,  8); loadkeys(r0,r4,r2,r1,  4);
	S2(r0,r4,r2,r1,r3); storekeys(r3,r4,r0,r1,  4); loadkeys(r3,r4,r0,r1,  0);
	S3(r3,r4,r0,r1,r2); storekeys(r1,r2,r4,r3,  0);

	return 0;
}

#ifndef USE_ASM_X86
void
serpent_encrypt(uint8_t *dst, const uint8_t *src, const uint32_t *expkey)
{
	const uint32_t	*k = expkey;
	const uint32_t	*s = (const uint32_t *)src;

	uint32_t	*d = (uint32_t *)dst;
	uint32_t	 r0, r1, r2, r3, r4;

	r0 = le32toh(s[0]);
	r1 = le32toh(s[1]);
	r2 = le32toh(s[2]);
	r3 = le32toh(s[3]);

				 K(r0,r1,r2,r3,0);
	S0(r0,r1,r2,r3,r4);	LK(r2,r1,r3,r0,r4,1);
	S1(r2,r1,r3,r0,r4);	LK(r4,r3,r0,r2,r1,2);
	S2(r4,r3,r0,r2,r1);	LK(r1,r3,r4,r2,r0,3);
	S3(r1,r3,r4,r2,r0);	LK(r2,r0,r3,r1,r4,4);
	S4(r2,r0,r3,r1,r4);	LK(r0,r3,r1,r4,r2,5);
	S5(r0,r3,r1,r4,r2);	LK(r2,r0,r3,r4,r1,6);
	S6(r2,r0,r3,r4,r1);	LK(r3,r1,r0,r4,r2,7);
	S7(r3,r1,r0,r4,r2);	LK(r2,r0,r4,r3,r1,8);
	S0(r2,r0,r4,r3,r1);	LK(r4,r0,r3,r2,r1,9);
	S1(r4,r0,r3,r2,r1);	LK(r1,r3,r2,r4,r0,10);
	S2(r1,r3,r2,r4,r0);	LK(r0,r3,r1,r4,r2,11);
	S3(r0,r3,r1,r4,r2);	LK(r4,r2,r3,r0,r1,12);
	S4(r4,r2,r3,r0,r1);	LK(r2,r3,r0,r1,r4,13);
	S5(r2,r3,r0,r1,r4);	LK(r4,r2,r3,r1,r0,14);
	S6(r4,r2,r3,r1,r0);	LK(r3,r0,r2,r1,r4,15);
	S7(r3,r0,r2,r1,r4);	LK(r4,r2,r1,r3,r0,16);
	S0(r4,r2,r1,r3,r0);	LK(r1,r2,r3,r4,r0,17);
	S1(r1,r2,r3,r4,r0);	LK(r0,r3,r4,r1,r2,18);
	S2(r0,r3,r4,r1,r2);	LK(r2,r3,r0,r1,r4,19);
	S3(r2,r3,r0,r1,r4);	LK(r1,r4,r3,r2,r0,20);
	S4(r1,r4,r3,r2,r0);	LK(r4,r3,r2,r0,r1,21);
	S5(r4,r3,r2,r0,r1);	LK(r1,r4,r3,r0,r2,22);
	S6(r1,r4,r3,r0,r2);	LK(r3,r2,r4,r0,r1,23);
	S7(r3,r2,r4,r0,r1);	LK(r1,r4,r0,r3,r2,24);
	S0(r1,r4,r0,r3,r2);	LK(r0,r4,r3,r1,r2,25);
	S1(r0,r4,r3,r1,r2);	LK(r2,r3,r1,r0,r4,26);
	S2(r2,r3,r1,r0,r4);	LK(r4,r3,r2,r0,r1,27);
	S3(r4,r3,r2,r0,r1);	LK(r0,r1,r3,r4,r2,28);
	S4(r0,r1,r3,r4,r2);	LK(r1,r3,r4,r2,r0,29);
	S5(r1,r3,r4,r2,r0);	LK(r0,r1,r3,r2,r4,30);
	S6(r0,r1,r3,r2,r4);	LK(r3,r4,r1,r2,r0,31);
	S7(r3,r4,r1,r2,r0);	 K(r0,r1,r2,r3,32);

	d[0] = htole32(r0);
	d[1] = htole32(r1);
	d[2] = htole32(r2);
	d[3] = htole32(r3);
}
#endif
