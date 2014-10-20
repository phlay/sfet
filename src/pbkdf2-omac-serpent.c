/* This file implements pbkdf2 using omac-serpent as keyed PRF.
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
#include <endian.h>
#include <string.h>

#include "utils.h"
#include "serpent.h"
#include "omac-serpent.h"
#include "pbkdf2-omac-serpent.h"


int
pbkdf2_omac_serpent(uint8_t *out, size_t outlen,
		    const char *passwd,
		    const uint8_t *salt, size_t saltlen,
		    uint64_t iter)
{
	uint32_t serpkey[SERPENT_EXPKEY_WORDS];
	omac_serpent_key_t omac_key;
	omac_serpent_t omac, omac_template;
	
	uint32_t i, be32i;
	uint64_t j;
	int k;
	
	uint8_t	U[16], tmptag[16];
	size_t need;

	/* XXX compress password into 32 byte serpent key size
	 * XXX to allow for longer passwords.
	 */
	
	if (serpent_setkey(serpkey, (uint8_t*)passwd, strlen(passwd)) == -1)
		return -1;
	
	omac_serpent_setkey(&omac_key, serpkey);
	omac_serpent_init(&omac_template, 0);
	omac_serpent_update(&omac_template, &omac_key, salt, saltlen);

	for (i = 1; outlen > 0; i++) {
		memcpy(&omac, &omac_template, sizeof(omac_serpent_t));
		
		be32i = htobe32(i);
		omac_serpent_update(&omac, &omac_key, (uint8_t*)&be32i, sizeof(be32i));
		omac_serpent_finalize(&omac, &omac_key, tmptag);
		memcpy(U, tmptag, 16);
	
		for (j = 2; j <= iter; j++) {
			omac_serpent_init(&omac, 0);
			omac_serpent_update(&omac, &omac_key, tmptag, 16);
			omac_serpent_finalize(&omac, &omac_key, tmptag);

			for (k = 0; k < 16; k++)
				U[k] ^= tmptag[k];
		}

		need = MIN(16, outlen);
		
		memcpy(out, U, need);
		out += need;
		outlen -= need;
	}

	/* clean stack of sensible data */
	burn(tmptag, 16);
	burn(&omac, sizeof(omac));
	burn(&omac_template, sizeof(omac_template));
	burn(&omac_key, sizeof(omac_key));
	burn(serpkey, sizeof(serpkey));

	return 0;
}
