#ifndef POLY1305_SERPENT_H
#define POLY1305_SERPENT_H

#include <stdint.h>

#include "poly1305.h"

void	poly1305_serpent_init(struct poly1305 *ctx,
		const uint8_t kr[32], const uint8_t nonce[16]);

#endif
