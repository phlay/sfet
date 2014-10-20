#ifndef PBKDF2_OMAC_SERPENT_H
#define PBKDF2_OMAC_SERPENT_H

#include <stdint.h>
#include <stddef.h>

int	 pbkdf2_omac_serpent(uint8_t *out, size_t outlen,
			     const char *passwd,
			     const uint8_t *salt, size_t saltlen,
			     uint64_t iter);

#endif
