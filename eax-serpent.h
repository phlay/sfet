#ifndef SERPENT_EAX_H
#define SERPENT_EAX_H

#include <stdint.h>
#include <stddef.h>

#include "serpent.h"
#include "omac-serpent.h"


typedef struct {
	uint32_t		key[SERPENT_EXPKEY_WORDS];

	uint8_t			ctr[16];	/* counter */
	uint8_t			ctrenc[16];	/* encrypted counter */
	size_t			ctrused;	/* < 16, used bytes of ctrenc */

	uint8_t			N[16];		/* omac-tag of nonce */

	omac_serpent_key_t	omac_key;	/* key for all omac calculations */

	omac_serpent_t		omacH;		/* omac struct for header */
	omac_serpent_t		omacC;		/* omac struct for cipher text */

} eax_serpent_t;


int	eax_serpent_init(eax_serpent_t *eax, const uint8_t *key, size_t keylen);
void	eax_serpent_nonce(eax_serpent_t *eax, const uint8_t *nonce, size_t nolen);
void	eax_serpent_header(eax_serpent_t *eax, const uint8_t *header, size_t headerlen);
void	eax_serpent_encrypt(eax_serpent_t *eax, uint8_t *ct, const uint8_t *pt, size_t len);
void	eax_serpent_decrypt(eax_serpent_t *eax, uint8_t *pt, const uint8_t *ct, size_t len);
void	eax_serpent_tag(eax_serpent_t *eax, uint8_t tag[16]);


#endif
