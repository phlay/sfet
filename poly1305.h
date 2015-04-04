#ifndef POLY1305
#define POLY1305

#include <stdint.h>
#include <stddef.h>


#ifdef __LP64__

typedef __uint128_t uint128_t;
typedef __int128_t int128_t;

typedef int64_t limb_t;
typedef int128_t llimb_t;

#define LIMB_NUM	3

#else

typedef int32_t limb_t;
typedef int64_t llimb_t;

#define LIMB_NUM	5

#endif


/*
 * element of the field Z / (2^130-5)
 */
typedef limb_t elem_t[LIMB_NUM];


struct poly1305 {
	elem_t		state;
	elem_t		r;

	limb_t		sr[LIMB_NUM-1];

	uint8_t		secret[16];

	uint8_t		buffer[17];
	uint8_t		fill;
};


void	poly1305_init(struct poly1305 *ctx, const uint8_t r[16], const uint8_t s[16]);
void	poly1305_update(struct poly1305 *ctx, const uint8_t *data, size_t len);
void	poly1305_mac(struct poly1305 *ctx, uint8_t mac[16]);


#endif
