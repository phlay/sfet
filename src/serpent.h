#ifndef SERPENT_H
#define SERPENT_H

#include <stdint.h>

/* Key is padded to the maximum of 256 bits before round key generation.
 * Any key length <= 256 bits (32 bytes) is allowed by the algorithm.
 */

#define SERPENT_MIN_KEY_SIZE		  0
#define SERPENT_MAX_KEY_SIZE		 32
#define SERPENT_EXPKEY_WORDS		132
#define SERPENT_BLOCK_SIZE		 16


int	serpent_setkey(uint32_t *expkey, const uint8_t *key, unsigned int keylen);
void	serpent_encrypt(const uint32_t *expkey, uint8_t *dst, const uint8_t *src);


#endif
