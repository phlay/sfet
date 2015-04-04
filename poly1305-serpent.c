#include <stdint.h>
#include <string.h>

#include "poly1305.h"
#include "serpent.h"
#include "poly1305-serpent.h"

void
poly1305_serpent_setkey(struct poly1305_serpent *ctx, const uint8_t kr[32])
{
	serpent_setkey(ctx->expkey, kr, 16);
	memcpy(ctx->r, kr+16, 16);
}

void
poly1305_serpent_nonce(struct poly1305_serpent *ctx, const uint8_t nonce[16])
{
	uint8_t	s[16];

	serpent_encrypt(s, nonce, ctx->expkey);
	poly1305_init(&ctx->poly1305, ctx->r, s);
	//poly1305_nonce(&ctx->poly1305, s);
}
