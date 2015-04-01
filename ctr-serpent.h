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


#endif
