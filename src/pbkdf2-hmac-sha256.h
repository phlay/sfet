#ifndef PBKDF2_SHA256
#define PBKDF2_SHA256

#include <stddef.h>
#include <stdint.h>

void
pbkdf2_hmac_sha256(uint8_t *out, size_t outlen,
		   const char *passwd, size_t passlen,
		   const uint8_t *salt, size_t saltlen,
		   uint64_t iter);

#endif
