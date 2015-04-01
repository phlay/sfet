#include <stdint.h>

#include "poly1305.h"
#include "serpent.h"
#include "poly1305-serpent.h"

void
poly1305_serpent_init(struct poly1305 *ctx, const uint8_t kr[32], const uint8_t nonce[16])
{
	uint32_t expkey[SERPENT_EXPKEY_WORDS];
	uint8_t	secret[16];

	serpent_setkey(expkey, kr, 16);
	serpent_encrypt(secret, nonce, expkey);

	poly1305_init(ctx, kr+16, secret);
}
