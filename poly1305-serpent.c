#include <stdint.h>
#include <string.h>

#include "poly1305.h"
#include "serpent.h"
#include "poly1305-serpent.h"

void
poly1305_serpent_setkey(struct poly1305_serpent *ctx, const uint8_t kr[32])
{
	/* expand serpent key */
	serpent_setkey(ctx->expkey, kr, 16);

	/* set poly1305 key */
	poly1305_setkey(&ctx->poly1305, kr+16);
}


void
poly1305_serpent_authdata(struct poly1305_serpent *ctx,
			  const uint8_t *data, size_t len,
			  const uint8_t nonce[16],
			  uint8_t mac[16])
{
	uint8_t	s[16];

	/* encrypt nonce for poly1305 */
	serpent_encrypt(s, nonce, ctx->expkey);

	/* reset poly1305 with encrypted nonce */
	poly1305_init(&ctx->poly1305, s);

	/* authorize data */
	poly1305_update(&ctx->poly1305, data, len);
	poly1305_mac(&ctx->poly1305, mac);
}
