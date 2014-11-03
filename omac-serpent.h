#ifndef OMAC_SERPENT_H
#define OMAC_SERPENT_H

#include <stdint.h>
#include <stddef.h>

#include "serpent.h"

/*
 * we have a seperate _key structure because we usually calculate multiple
 * omacs for the same key.
 */
typedef struct {
	uint32_t	 expkey[SERPENT_EXPKEY_WORDS];
	uint8_t		 B[16];
	uint8_t		 P[16];
} omac_serpent_key_t;


/*
 * context structure for serpent-omac calculations
 */
typedef struct {
	uint8_t		tag[16];
	uint8_t		buf[16];
	int		fill;
} omac_serpent_t;


void	 omac_serpent_setkey(omac_serpent_key_t *omac_key, const uint32_t *key);
void	 omac_serpent_init(omac_serpent_t *ctx, uint8_t t);
void	 omac_serpent_update(omac_serpent_t *omac,
			     const omac_serpent_key_t *key,
			     const void *data, size_t len);
void	 omac_serpent_finalize(omac_serpent_t *omac,
			       const omac_serpent_key_t *key, uint8_t tag[16]);

#endif
