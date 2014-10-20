/* omac-serpent - implements the omac algorithm using serpent
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.#include <stdint.h>
 */

#include <stddef.h>
#include <string.h>

#include "serpent.h"
#include "omac-serpent.h"


/*
 * xtimes - helper function for omac_serpent_setkey()
 * 
 * The input e is interpreted as element of GF(2^128) with minimal polynom
 * X^128 + X^7 + X^2 + X + 1 (= (1<<128) | 0x87) and e*X is calculated and
 * returned in out.
 */
static void
xtimes(uint8_t out[16], const uint8_t e[16])
{
	uint8_t carry, temp;
	int i;

	/* we set carry to X^7 + X^2 + X + 1 = 0x87 if first bit of e
	 * is set and to 0 otherwise, without leaking timing information.
	 */
	carry = ~((e[0] >> 7)-1) & 0x87;
	
	for (i = 15; i >= 0; i--) {
		temp = (e[i] >> 7) & 0x01;
		out[i] = (e[i] << 1) ^ carry;
		carry = temp;
	}
}


/*
 * omac_serpent_setkey - initialize an omac-key from an expanded serpent key.
 */
void
omac_serpent_setkey(omac_serpent_key_t *omac_key, const uint32_t *expkey)
{
	/* copy expanded serpent key */
	memcpy(omac_key->expkey, expkey, SERPENT_EXPKEY_WORDS * sizeof(uint32_t));
	
	/* last block in OMAC is xor-ed with B:=X*encrypt(0^128) if it
	 * is complete and with P:=X^2*encrypt(0^128) otherwise. The
	 * multiplication with X is done in a special galois-field
	 * (see xtimes above).
	 */	
	memset(omac_key->B, 0, 16);
	serpent_encrypt(expkey, omac_key->B, omac_key->B);
	xtimes(omac_key->B, omac_key->B);
	xtimes(omac_key->P, omac_key->B);
}


/*
 * omac_serpent_init - initializes an omac context structure.
 *
 * NOTE: parameter t is a tweak used by EAX-mode, use t=0 for usual omac.
 */
void
omac_serpent_init(omac_serpent_t *ctx, uint8_t t)
{
	memset(ctx->tag, 0, 15);
	ctx->tag[15] = t;
	ctx->fill = 0;
}

/*
 * omac_serpent_update - adds new data to an omac context
 */
void
omac_serpent_update(omac_serpent_t *omac, const omac_serpent_key_t *key,
		    const uint8_t *data, size_t len)
{
	int i;

	/* start with carryover */
	if (omac->fill > 0) {
		while (omac->fill < 16 && len > 0) {
			omac->buf[omac->fill++] = *data++;
			len--;
		}
		
		/* not even enough data to fillup buffer? */
		if (omac->fill < 16)
			return;

		/* buffer is full => do one OMAC round */
		serpent_encrypt(key->expkey, omac->tag, omac->tag);
		for (i = 0; i < 16; i++)
			omac->tag[i] ^= omac->buf[i];
	}
		
	/* now loop over data */
	for (; len >= 16; len -= 16) {
		serpent_encrypt(key->expkey, omac->tag, omac->tag);
		for (i = 0; i < 16; i++)
			omac->tag[i] ^= *data++;
	}

	/* copy left-over in our buffer */
	for (i = 0; i < len; i++)
		omac->buf[i] = *data++;
	
	omac->fill = len;
}


/*
 * omac_serpent_finalize - ends an omac calculation and returns hash-tag in tag.
 *
 * NOTE A: After using this function, the context must be reset with
 *	   omac_serpent_init().
 * 
 * NOTE B: if the message is 0 bytes long, we do NOT pad it (even
 * 	   though the EAX paper states to do so), because otherwise
 * 	   the test vectors (the first one from the same paper) won't
 * 	   work.
 */
void
omac_serpent_finalize(omac_serpent_t *omac,
		      const omac_serpent_key_t *key,
		      uint8_t tag[16])
{
	int i;

	if (omac->fill) {
		/* last block is incomplete => copy what we have */
		serpent_encrypt(key->expkey, omac->tag, omac->tag);
		for (i = 0; i < omac->fill; i++)
			omac->tag[i] ^= omac->buf[i];
		
		/* pad */
		omac->tag[i] ^= 0x80;
		
		for (i = 0; i < 16; i++)
			omac->tag[i] ^= key->P[i];

	} else {
		/* last block is complete */
		for (i = 0; i < 16; i++)
			omac->tag[i] ^= key->B[i];
	}

	serpent_encrypt(key->expkey, tag, omac->tag);
}
