/*
 * ctr-serpent - this module implements counter mode for serpent block cipher
 */

#include <string.h>

#include "serpent.h"
#include "ctr-serpent.h"


void
ctr_serpent_init(struct ctr_serpent *ctx, const uint8_t key[32])
{
	serpent_setkey(ctx->expkey, key, 32);
}

void
ctr_serpent_nonce(struct ctr_serpent *ctx, const uint8_t nonce[8])
{
	memcpy(ctx->ctr, nonce, 8);
	memset(ctx->ctr+8, 0, 8);
	ctx->ctrused = 0;
}


/*
 * ctr_serpent_crypt - counter-mode for serpent
 *
 * dst must point to a buffer with at least len bytes of space.
 */
void
ctr_serpent_crypt(struct ctr_serpent *ctx, uint8_t *dst,
		  const uint8_t *src, size_t len)
{
	int i;

	/* start with carry-over in our encrypted-counter-buffer */
	if (ctx->ctrused > 0) {
		while (ctx->ctrused < 16 && len > 0) {
			*dst++ = *src++ ^ ctx->ctrenc[ctx->ctrused++];
			len--;
		}
		if (ctx->ctrused < 16)
			return;
	}

	/*
	 * now ctx->ctrenc is completly used
	 */


#ifdef USE_ASM_AVX
	/*
	 * loop over 8*16 byte chunks with optimized assembler routine
	 */
	for (; len >= 8*16; len -= 8*16, dst += 8*16, src += 8*16)
		serpent8x_ctr(dst, src, ctx->expkey, ctx->ctr);
#endif

	/*
	 * now loop over remaining 16 byte chunks with regular C code
	 */
	for (; len >= 16; len -= 16) {
		/* encrypt and advance counter */
		serpent_encrypt(ctx->ctrenc, ctx->ctr, ctx->expkey);
		for (i = 15; i >= 0 && ++ctx->ctr[i] == 0; i--);

		/* encrypt data */
		for (i = 0; i < 16; i++)
			*dst++ = *src++ ^ ctx->ctrenc[i];
	}

	/* we have len < 16: encrypt left-over and set ctrused accordingly */
	if (len > 0) {
		/* encrypt and advance counter */
		serpent_encrypt(ctx->ctrenc, ctx->ctr, ctx->expkey);
		for (i = 15; i >= 0 && ++ctx->ctr[i] == 0; i--);

		/* encrypt data */
		for (i = 0; i < len; i++)
			*dst++ = *src++ ^ ctx->ctrenc[i];
	}
	ctx->ctrused = len;
}
