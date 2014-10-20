/* Incremental EAX-mode using the serpent block cipher.
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. 
 */

#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "serpent.h"
#include "omac-serpent.h"
#include "eax-serpent.h"


/*
 * Local functions
 */


/*
 * serpent_ctr - counter-mode for serpent, used internally by EAX-mode
 *
 * dst must point to a buffer with at least len bytes of space.
 * used attributes of eax: key, ctr, ctrenc, ctrused.
 */
static void
serpent_ctr(eax_serpent_t *eax, uint8_t *dst, const uint8_t *src, size_t len)
{
	int i;

	/* start with carry-over in our encrypted-counter-buffer */
	if (eax->ctrused > 0) {
		while (eax->ctrused < 16 && len > 0) {
			*dst++ = *src++ ^ eax->ctrenc[eax->ctrused++];
			len--;
		}
		if (eax->ctrused < 16)
			return;
		
		/* advance and encrypt counter */
		for (i = 15; i >= 0 && ++eax->ctr[i] == 0; i--);
		serpent_encrypt(eax->key, eax->ctrenc, eax->ctr);
	}

	/*
	 * now eax->ctrenc is completly used. eax->ctrused may be 16
	 * at this point, but this will be fixed after the mainloop
	 */
	
	/* mainloop: encrypt src to dst in 16 byte chunks  */
	for (; len >= 16; len -= 16) {
		for (i = 0; i < 16; i++)
			*dst++ = *src++ ^ eax->ctrenc[i];
		
		for (i = 15; i >= 0 && ++eax->ctr[i] == 0; i--);
		serpent_encrypt(eax->key, eax->ctrenc, eax->ctr);
	}
	
	/* we have len < 16: encrypt left-over and set ctrused accordingly */
	for (i = 0; i < len; i++)
		*dst++ = *src++ ^ eax->ctrenc[i];

	eax->ctrused = len;
}



/*
 * Exported functions
 */


/*
 * eax_serpent_init - initialize eax context, this is done once per session key.
 *
 * NOTE: before using any function on the EAX context eax_serpent_nonce()
 *	 MUST be called (see warning there).
 */
int
eax_serpent_init(eax_serpent_t *eax, const uint8_t *key, size_t keylen)
{
	/* start with initializing serpent key */
	if (serpent_setkey(eax->key, key, keylen) == -1)
		return -1;

	/* prepare omac key */
	omac_serpent_setkey(&eax->omac_key, eax->key);
	
	return 0;
}


/*
 * eax_serpent_nonce - registers a new nonce and resets the eax-context for reuse.
 *
 * WARNING A: The nonces used for this function MUST NOT repeat for a fixed key!
 *
 * WARNING B: This MUST be called after eax_serpent_init() or
 * eax_serpent_tag() and before anything other is done with this mode!
 */
void
eax_serpent_nonce(eax_serpent_t *eax, const uint8_t *nonce, size_t nolen)
{
	omac_serpent_t omac_nonce;
	
	/* calculate N tag from nonce */
	omac_serpent_init(&omac_nonce, 0);
	omac_serpent_update(&omac_nonce, &eax->omac_key, nonce, nolen);
	omac_serpent_finalize(&omac_nonce, &eax->omac_key, eax->N);
	burn(&omac_nonce, sizeof(omac_serpent_t));
	
	/* initialize counter as copy from N */
	memcpy(eax->ctr, eax->N, 16);
	serpent_encrypt(eax->key, eax->ctrenc, eax->ctr);
	eax->ctrused = 0;

	/* initialize other omacs, H for header and C for ciphertext */
	omac_serpent_init(&eax->omacH, 1);
	omac_serpent_init(&eax->omacC, 2);
}


/*
 * eax_serpent_header - registers data to authenticate without encryption
 */
void
eax_serpent_header(eax_serpent_t *eax, const uint8_t *header, size_t headerlen)
{
	omac_serpent_update(&eax->omacH, &eax->omac_key, header, headerlen);
}


/*
 * eax_serpent_encrypt - encrypts and authenticate len bytes of plain text (pt).
 *
 * ct must point to a buffer holding at least len bytes.
 */
void
eax_serpent_encrypt(eax_serpent_t *eax, uint8_t *ct, const uint8_t *pt, size_t len)
{
	serpent_ctr(eax, ct, pt, len);
	omac_serpent_update(&eax->omacC, &eax->omac_key, ct, len);
}

/*
 * eax_serpent_decrypt - authenticates and decryptes len bytes of cipher text (ct).
 *
 * pt must point to a buffer holding at least len bytes.
 */
void
eax_serpent_decrypt(eax_serpent_t *eax, uint8_t *pt, const uint8_t *ct, size_t len)
{
	omac_serpent_update(&eax->omacC, &eax->omac_key, ct, len);
	serpent_ctr(eax, pt, ct, len);
}


/*
 * eax_serpent_tag - finalize an encryption/decryption and returns a hash-tag.
 *
 * NOTE: if, after using this function, another packet should be en- or decrypted,
 * a new nonce must be registered using eax_serpent_nonce().
 */
void
eax_serpent_tag(eax_serpent_t *eax, uint8_t tag[16])
{
	uint8_t H[16], C[16];
	int i;

	/* finalize omacs */
	omac_serpent_finalize(&eax->omacH, &eax->omac_key, H);
	omac_serpent_finalize(&eax->omacC, &eax->omac_key, C);

	/* compute resulting tag */
	for (i = 0; i < 16; i++)
		tag[i] = eax->N[i] ^ H[i] ^ C[i];

	/* cleanup stack */
	burn(H, sizeof(H));
	burn(C, sizeof(C));
}
