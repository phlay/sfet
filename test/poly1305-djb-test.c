/* selftest based on http://cr.yp.to/mac/test.html */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/aes.h>

#include "poly1305.h"


#define MAXLEN 1000

static inline void
aes(uint8_t out[16], const uint8_t k[16], const uint8_t blk[16])
{
	AES_KEY expkey;
	AES_set_encrypt_key(k, 128, &expkey);
	AES_encrypt(blk, out, &expkey);
}

static inline void
poly1305aes_authenticate(uint8_t out[16],
			 const uint8_t kr[32],
			 const uint8_t nonce[16],
			 const uint8_t *msg,
			 size_t len)
{
	struct poly1305 ctx;
	uint8_t encno[16];

	poly1305_setkey(&ctx, kr+16);

	aes(encno, kr, nonce);
	poly1305_init(&ctx, encno);

	poly1305_update(&ctx, msg, len);
	poly1305_mac(&ctx, out);
}


unsigned char out[16];
unsigned char kr[32];
unsigned char n[16];
unsigned char m[MAXLEN];

int main()
{
	int loop;
	int len;
	int i;
	int x;
	int y;

	for (loop = 0; loop < 1000000; ++loop) {
		len = 0;

		for (;;) {
			poly1305aes_authenticate(out,kr,n,m,len);

			for (i = 0;i < 16;++i) printf("%02x",(unsigned int) out[i]);
			printf("\n");
			x = random() & 15;
			y = 1 + (random() % 255);
			if (len >= MAXLEN)
				break;

			n[0] ^= loop;

			for (i = 0;i < 16;++i)
				n[i] ^= out[i];
			if (len % 2)
				for (i = 0;i < 16;++i)
					kr[i] ^= out[i];
			if (len % 3)
				for (i = 0;i < 16;++i)
					kr[i + 16] ^= out[i];

			m[len++] ^= out[0];
		}
	}
	return 0;
}
