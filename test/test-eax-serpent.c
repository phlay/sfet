#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <riddler.h>

#include "eax-serpent.h"

#define BUFLEN		(16*1024)

struct {
	uint8_t		key[16];
	uint8_t		nonce[16];
	size_t		headerlen;
	uint8_t		header[BUFLEN];
	size_t		msglen;
	uint8_t		msg[BUFLEN];
	uint8_t		ct[BUFLEN];
	uint8_t		tag[16];
} table[] = {
	#include "eax-serpent-table.h"
};

const int table_num = sizeof(table) / sizeof(table[0]);



int main()
{
	eax_serpent_t ctx;
	uint8_t check[BUFLEN];
	uint8_t checktag[16];
	int i;

	for (i = 0; i < table_num; i++) {
		eax_serpent_init(&ctx, table[i].key, 16);

		/* encrypt test */
		eax_serpent_nonce(&ctx, table[i].nonce, 16);
		eax_serpent_header(&ctx, table[i].header, table[i].headerlen);
		eax_serpent_encrypt(&ctx, check, table[i].msg, table[i].msglen);
		eax_serpent_tag(&ctx, checktag);

		if (memcmp(check, table[i].ct, table[i].msglen) != 0) {
			fprintf(stderr, "eax-serpent encryption test %d failed\n", i+1);
			return 1;
		}

		if (memcmp(checktag, table[i].tag, 16) != 0) {
			fprintf(stderr, "eax-serpent generating tag %d failed\n", i+1);
			return 1;
		}

		/* decryption test */
		eax_serpent_nonce(&ctx, table[i].nonce, 16);
		eax_serpent_header(&ctx, table[i].header, table[i].headerlen);
		eax_serpent_decrypt(&ctx, check, table[i].ct, table[i].msglen);
		eax_serpent_tag(&ctx, checktag);

		if (memcmp(checktag, table[i].tag, 16) != 0) {
			fprintf(stderr, "eax-serpent verify tag %d failed\n", i+1);
			return 1;
		}

		if (memcmp(check, table[i].msg, table[i].msglen) != 0) {
			fprintf(stderr, "eax-serpent decryption %d failed\n", i+1);
			return 1;
		}
	}

	return 0;
}
