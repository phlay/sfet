/* This module implements pbkdf2-hmac-sha256.
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <endian.h>

#include "utils.h"
#include "sha256.h"
#include "pbkdf2-hmac-sha256.h"


#define IPAD	0x36
#define OPAD	0x5c



static void
hmac_sha256_init(sha256ctx *ctx, const uint8_t key[32])
{
	uint8_t pad[64];
	int i;
	
	/* apply inner padding */
	for (i = 0; i < 32; i++)
		pad[i] = key[i] ^ IPAD;
	for (i = 32; i < 64; i++)
		pad[i] = IPAD;

	sha256_init(ctx);
	sha256_add(ctx, pad, 64);
}


static void
hmac_sha256_done(sha256ctx *ctx, const uint8_t key[32], uint8_t result[32])
{
	uint8_t pad[64];
	uint8_t ihash[32];
	int i;

	/* construct outer padding */
	for (i = 0; i < 32; i++)
		pad[i] = key[i] ^ OPAD;
	for (i = 32; i < 64; i++)
		pad[i] = OPAD;

	/* finalize inner hash */
	sha256_done(ctx, ihash);

	sha256_init(ctx);
	sha256_add(ctx, pad, 64);
	sha256_add(ctx, ihash, 32);
	sha256_done(ctx, result);
}


void
pbkdf2_hmac_sha256(uint8_t *out, size_t outlen,
		   const uint8_t *passwd, size_t passlen,
		   const uint8_t *salt, size_t saltlen,
		   uint64_t iter)
{
	sha256ctx hmac, hmac_template;
	uint32_t i, be32i;
	uint64_t j;
	int k;
	
	uint8_t key[32];
	uint8_t	U[32], tmptag[32];
	size_t need;

	/*
	 * vartime code to handle password hmac-style
	 */
	if (passlen > 32) {
		sha256_init(&hmac);
		sha256_add(&hmac, passwd, passlen);
		sha256_done(&hmac, key);
	} else {
		memcpy(key, passwd, passlen);
		memset(key + passlen, 0, 32-passlen);
	}

	hmac_sha256_init(&hmac_template, key);
	sha256_add(&hmac_template, salt, saltlen);

	for (i = 1; outlen > 0; i++) {
		memcpy(&hmac, &hmac_template, sizeof(sha256ctx));
		
		be32i = htobe32(i);
		sha256_add(&hmac, (uint8_t*)&be32i, sizeof(be32i));
		hmac_sha256_done(&hmac, key, tmptag);
		memcpy(U, tmptag, 32);
	
		for (j = 2; j <= iter; j++) {
			hmac_sha256_init(&hmac, key);
			sha256_add(&hmac, tmptag, 32);
			hmac_sha256_done(&hmac, key, tmptag);

			for (k = 0; k < 32; k++)
				U[k] ^= tmptag[k];
		}

		need = MIN(32, outlen);
		
		memcpy(out, U, need);
		out += need;
		outlen -= need;
	}
}
