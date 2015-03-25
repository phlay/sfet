#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "poly1305.h"


#ifdef __LP64__

/*
 * 64 bit optimized
 */

static inline void
import1305(elem_t out, const uint8_t x[16], uint8_t x16)
{
	/* 48 bits in limb 1 */
	out[0] = x[0] | ((limb_t)x[1]<<8) | ((limb_t)x[2]<<16)
		| ((limb_t)x[3]<<24) | ((limb_t)x[4]<<32)
		| ((limb_t)x[5]<<40);


	/* put 40 bits into limb 2.
	 * since limb 1 is 4 bit overfilled, we need a shift here
	 */
	out[1] = ((limb_t)x[6]<<4) | ((limb_t)x[7]<<12)
		| ((limb_t)x[8]<<20) | ((limb_t)x[9] << 28)
		| ((limb_t)x[10] << 36);

	/* last 40 bits go into limb 3 here */
	out[2] = x[11] | ((limb_t)x[12]<<8)
		| ((limb_t)x[13]<<16) | ((limb_t)x[14]<<24)
		| ((limb_t)x[15]<<32) | ((limb_t)x16<<40);
}



static inline void
export1305(uint8_t out[16], const elem_t in)
{
	elem_t tmp;

	/*
	 * reduce modulo 2^130 - 5
	 */

	/* first round with offset +5 */
	tmp[0] = in[0] + 5;
	tmp[1] = in[1] + (tmp[0] >> 44);
	tmp[2] = in[2] + (tmp[1] >> 44);
	tmp[0] = (tmp[0] & 0xfffffffffff) + 5*(tmp[2] >> 42);
	tmp[1] &= 0xfffffffffff;
	tmp[2] &= 0x3ffffffffff;

	/* second round */
	tmp[1] += tmp[0] >> 44;
	tmp[2] += tmp[1] >> 44;
	tmp[0] = (tmp[0] & 0xfffffffffff) + 5*(tmp[2] >> 42);
	tmp[1] &= 0xfffffffffff;
	tmp[2] &= 0x3ffffffffff;

	/* last round with offset -5 */
	tmp[0] -= 5;
	tmp[1] += tmp[0] >> 44;
	tmp[2] += tmp[1] >> 44;
	tmp[0] = (tmp[0] & 0xfffffffffff) + 5*(tmp[2] >> 42);
	tmp[1] &= 0xfffffffffff;
	tmp[2] &= 0x3ffffffffff;

	/*
	 * write out tmp modulo 2^128
	 */
	out[0] = tmp[0] & 0xff;
	out[1] = (tmp[0] >> 8) & 0xff;
	out[2] = (tmp[0] >> 16) & 0xff;
	out[3] = (tmp[0] >> 24) & 0xff;
	out[4] = (tmp[0] >> 32) & 0xff;
	out[5] = (tmp[0] >> 40) & 0x0f;

	tmp[1] <<= 4;
	out[5] |= tmp[1] & 0xf0;
	out[6] = (tmp[1] >> 8) & 0xff;
	out[7] = (tmp[1] >> 16) & 0xff;
	out[8] = (tmp[1] >> 24) & 0xff;
	out[9] = (tmp[1] >> 32) & 0xff;
	out[10] = (tmp[1] >> 40) & 0xff;

	out[11] = tmp[2] & 0xff;
	out[12] = (tmp[2] >> 8) & 0xff;
	out[13] = (tmp[2] >> 16) & 0xff;
	out[14] = (tmp[2] >> 24) & 0xff;
	out[15] = (tmp[2] >> 32) & 0xff;
}


static inline void
horner1305(struct poly1305 *ctx, const uint8_t data[16], uint8_t bit128)
{
	llimb_t tmp[3];
	elem_t c;

	limb_t *s = ctx->state;
	limb_t *r = ctx->r;
	limb_t *sr = ctx->sr;

	/* add new data to state */
	import1305(c, data, bit128);
	s[0] += c[0];
	s[1] += c[1];
	s[2] += c[2];

	/* multiplication */
	tmp[0] = (llimb_t)s[0]*r[0] + (llimb_t)s[1]*sr[1] + (llimb_t)s[2]*sr[0];
	tmp[1] = (llimb_t)s[0]*r[1] + (llimb_t)s[1]*r[0] + (llimb_t)s[2]*sr[1];
	tmp[2] = (llimb_t)s[0]*r[2] + (llimb_t)s[1]*r[1] + (llimb_t)s[2]*r[0];

	/* carry */
	tmp[1] += tmp[0] >> 44;
	tmp[2] += tmp[1] >> 44;

	/* reduce and copy out */
	s[0] = tmp[0] & 0xfffffffffff;
	s[1] = tmp[1] & 0xfffffffffff;
	s[2] = tmp[2] & 0xfffffffffff;
	s[0] += 20*(tmp[2] >> 44);
}


#else

/*
 * 32bit code
 */

static inline void
import1305(elem_t out, const uint8_t x[16], uint8_t x16)
{
	out[0] = x[0] | ((limb_t)x[1] << 8) | ((limb_t)x[2] << 16) | ((limb_t)(x[3] & 0x03) << 24);
	out[1] = (x[3] >> 2) | ((limb_t)x[4] << 6) | ((limb_t)x[5] << 14) | ((limb_t)(x[6] & 0x0f) << 22);
	out[2] = (x[6] >> 4) | ((limb_t)x[7] << 4) | ((limb_t)x[8] << 12) | ((limb_t)(x[9] & 0x3f) << 20);
	out[3] = (x[9] >> 6) | ((limb_t)x[10] << 2) | ((limb_t)x[11] << 10) | ((limb_t)x[12] << 18);
	out[4] = x[13] | ((limb_t)x[14] << 8) | ((limb_t)x[15] << 16) | ((limb_t)x16 << 24);
}

static inline void
export1305(uint8_t out[16], const elem_t in)
{
	elem_t tmp;

	/* first round */
	tmp[0] = in[0] + 5;
	tmp[1] = in[1] + (tmp[0] >> 26);
	tmp[2] = in[2] + (tmp[1] >> 26);
	tmp[3] = in[3] + (tmp[2] >> 26);
	tmp[4] = in[4] + (tmp[3] >> 26);
	tmp[0] = (tmp[0] & 0x3ffffff) + 5*(tmp[4] >> 26);
	tmp[1] &= 0x3ffffff;
	tmp[2] &= 0x3ffffff;
	tmp[3] &= 0x3ffffff;
	tmp[4] &= 0x3ffffff;

	/* second round */
	tmp[1] += tmp[0] >> 26;
	tmp[2] += tmp[1] >> 26;
	tmp[3] += tmp[2] >> 26;
	tmp[4] += tmp[3] >> 26;
	tmp[0] = (tmp[0] & 0x3ffffff) + 5*(tmp[4] >> 26);
	tmp[1] &= 0x3ffffff;
	tmp[2] &= 0x3ffffff;
	tmp[3] &= 0x3ffffff;
	tmp[4] &= 0x3ffffff;

	/* third round */
	tmp[0] -= 5;
	tmp[1] += tmp[0] >> 26;
	tmp[2] += tmp[1] >> 26;
	tmp[3] += tmp[2] >> 26;
	tmp[4] += tmp[3] >> 26;
	tmp[0] = (tmp[0] & 0x3ffffff) + 5*(tmp[4] >> 26);
	tmp[1] &= 0x3ffffff;
	tmp[2] &= 0x3ffffff;
	tmp[3] &= 0x3ffffff;
	tmp[4] &= 0x3ffffff;

	/*
	 * now export modulo 2^128
	 */
	out[0] = tmp[0] & 0xff;
	out[1] = (tmp[0] >> 8) & 0xff;
	out[2] = (tmp[0] >> 16) & 0xff;
	out[3] = (tmp[0] >> 24) & 0x03;

	out[3] |= (tmp[1] << 2) & 0xff;
	out[4] = (tmp[1] >> 6) & 0xff;
	out[5] = (tmp[1] >> 14) & 0xff;
	out[6] = (tmp[1] >> 22) & 0x0f;

	out[6] |= (tmp[2] << 4) & 0xff;
	out[7] = (tmp[2] >> 4) & 0xff;
	out[8] = (tmp[2] >> 12) & 0xff;
	out[9] = (tmp[2] >> 20) & 0x3f;

	out[9] |= (tmp[3] << 6) & 0xff;
	out[10] = (tmp[3] >> 2) & 0xff;
	out[11] = (tmp[3] >> 10) & 0xff;
	out[12] = (tmp[3] >> 18) & 0xff;

	out[13] = tmp[4] & 0xff;
	out[14] = (tmp[4] >> 8) & 0xff;
	out[15] = (tmp[4] >> 16) & 0xff;
}



static inline void
horner1305(struct poly1305 *ctx, const uint8_t data[16], uint8_t bit128)
{
	llimb_t tmp[5];
	elem_t c;

	limb_t *s = ctx->state;
	limb_t *r = ctx->r;
	limb_t *sr = ctx->sr;

	/* add new data to state */
	import1305(c, data, bit128);
	s[0] += c[0];
	s[1] += c[1];
	s[2] += c[2];
	s[3] += c[3];
	s[4] += c[4];

	/* multiplicate with secret */
	tmp[0] = (llimb_t)s[0]*r[0] + (llimb_t)s[1]*sr[3]
		+ (llimb_t)s[2]*sr[2] + (llimb_t)s[3]*sr[1]
		+ (llimb_t)s[4]*sr[0];
	tmp[1] = (llimb_t)s[0]*r[1] + (llimb_t)s[1]*r[0]
		+ (llimb_t)s[2]*sr[3] + (llimb_t)s[3]*sr[2]
		+ (llimb_t)s[4]*sr[1];
	tmp[2] = (llimb_t)s[0]*r[2] + (llimb_t)s[1]*r[1]
		+ (llimb_t)s[2]*r[0] + (llimb_t)s[3]*sr[3]
		+ (llimb_t)s[4]*sr[2];
	tmp[3] = (llimb_t)s[0]*r[3] + (llimb_t)s[1]*r[2]
		+ (llimb_t)s[2]*r[1] + (llimb_t)s[3]*r[0]
		+ (llimb_t)s[4]*sr[3];
	tmp[4] = (llimb_t)s[0]*r[4] + (llimb_t)s[1]*r[3]
		+ (llimb_t)s[2]*r[2] + (llimb_t)s[3]*r[1]
		+ (llimb_t)s[4]*r[0];


	/* carry */
	tmp[1] += tmp[0] >> 26;
	tmp[2] += tmp[1] >> 26;
	tmp[3] += tmp[2] >> 26;
	tmp[4] += tmp[3] >> 26;


	/* reduce and copy to state */
	s[0] = tmp[0] & 0x3ffffff;
	s[1] = tmp[1] & 0x3ffffff;
	s[2] = tmp[2] & 0x3ffffff;
	s[3] = tmp[3] & 0x3ffffff;
	s[4] = tmp[4] & 0x3ffffff;
	s[0] += 5*(tmp[4] >> 26);
}

#endif

static inline void
add128(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
	int foo = 0;

	for (int i = 0; i < 16; i++) {
		foo += a[i] + b[i];
		out[i] = foo & 0xff;
		foo >>= 8;
	}
}



void
poly1305_init(struct poly1305 *ctx, const uint8_t r[16])
{
#if 1
	uint8_t prepr[16];

	/* prepare r */
	memcpy(prepr, r, 16);
	prepr[3] &= 0xf;
	prepr[4] &= 0xfc;
	prepr[7] &= 0xf;
	prepr[8] &= 0xfc;
	prepr[11] &= 0xf;
	prepr[12] &= 0xfc;
	prepr[15] &= 0xf;
	import1305(ctx->r, prepr, 0);
#else
	import1305(ctx->r, r, 0);
#endif


#ifdef __LP64__
	for (int i = 0; i < LIMB_NUM-1; i++)
		ctx->sr[i] = 20*ctx->r[i+1];
#else
	for (int i = 0; i < LIMB_NUM-1; i++)
		ctx->sr[i] = 5*ctx->r[i+1];
#endif

	/* init state */
	for (int i = 0; i < LIMB_NUM; i++)
		ctx->state[i] = 0;

	ctx->fill = 0;
}


void
poly1305_update(struct poly1305 *ctx, const uint8_t *data, size_t len)
{
	if (ctx->fill > 0) {
		int need = MIN(len, 16 - ctx->fill);

		memcpy(ctx->buffer+ctx->fill, data, need);
		ctx->fill += need;

		if (ctx->fill < 16)
			return;

		horner1305(ctx, ctx->buffer, 1);

		len -= need;
		data += need;
	}

	for (; len >= 16; len -= 16, data += 16)
		horner1305(ctx, data, 1);

	/* copy rest for next call */
	memcpy(ctx->buffer, data, len);
	ctx->fill = len;
}


void
poly1305_mac(struct poly1305 *ctx, const uint8_t encno[16], uint8_t mac[16])
{
	uint8_t pack[16];

	if (ctx->fill > 0) {
		/* pad buffer */
		ctx->buffer[ctx->fill++] = 1;
		for (int i = ctx->fill; i < 16; i++)
			ctx->buffer[i] = 0;

		horner1305(ctx, ctx->buffer, 0);
	}

	export1305(pack, ctx->state);
	add128(mac, pack, encno);
}
