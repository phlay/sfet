#ifndef CTR_SERPENT_H
#define CTR_SERPENT_H

#include <stdint.h>
#include <stddef.h>

#include "serpent.h"

struct ctr_serpent {
	uint32_t	 expkey[SERPENT_EXPKEY_WORDS];

	uint8_t		 ctr[16];	/* counter */
	uint8_t		 ctrenc[16];	/* encrypted counter */
	size_t		 ctrused;	/* < 16, used bytes of ctrenc */
};

void	 ctr_serpent_init(struct ctr_serpent *ctx, const uint8_t key[32]);
void	 ctr_serpent_nonce(struct ctr_serpent *ctx, const uint8_t nonce[8]);
void	 ctr_serpent_crypt(struct ctr_serpent *ctx, uint8_t *dst,
		  const uint8_t *src, size_t len);

#endif
