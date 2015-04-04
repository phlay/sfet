#ifndef POLY1305_SERPENT_H
#define POLY1305_SERPENT_H

#include <stdint.h>

#include "poly1305.h"
#include "serpent.h"

struct poly1305_serpent {
	struct poly1305		poly1305;

	uint8_t			r[16];	/* XXX */
	uint32_t		expkey[SERPENT_EXPKEY_WORDS];
};

void	poly1305_serpent_setkey(struct poly1305_serpent *ctx,
				const uint8_t kr[32]);

void	poly1305_serpent_nonce(struct poly1305_serpent *ctx,
			       const uint8_t nonce[16]);

#endif
