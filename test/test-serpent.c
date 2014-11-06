#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "serpent.h"


struct {
	uint8_t		key[16];
	uint8_t		plain[16];
	uint8_t		enc[16];
	uint8_t		enc100[16];
	uint8_t		enc1000[16];

} table128[] = {
	#include "serpent128-table.h"
};

const int table128_num = sizeof(table128) / sizeof(table128[0]);


struct {
	uint8_t		key[32];
	uint8_t		plain[16];
	uint8_t		enc[16];
	uint8_t		enc100[16];
	uint8_t		enc1000[16];
} table256[] = {
	#include "serpent256-table.h"
};

const int table256_num = sizeof(table256) / sizeof(table256[0]);




int main()
{
	uint32_t expkey[SERPENT_EXPKEY_WORDS];
	uint8_t check[16];
	int i, j;

	/* test serpent with 128key key */
	for (i = 0; i < table128_num; i++) {
		serpent_setkey(expkey, table128[i].key, 16);

		/* encryption test */
		serpent_encrypt(check, table128[i].plain, expkey);
		if (memcmp(check, table128[i].enc, 16) != 0) {
			fprintf(stderr, "serpent-128 encrypt test %d failed\n", i+1);
			return 1;
		}

		/* encrypt 99 times more */
		for (j = 0; j < 99; j++)
			serpent_encrypt(check, check, expkey);

		if (memcmp(check, table128[i].enc100, 16) != 0) {
			fprintf(stderr, "serpent-128 100x encrypt test %d failed\n", i+1);
			return 1;
		}

		/* encrypt 900 times more */
		for (j = 0; j < 900; j++)
			serpent_encrypt(check, check, expkey);

		if (memcmp(check, table128[i].enc1000, 16) != 0) {
			fprintf(stderr, "serpent-128 1000x encrypt test %d failed\n", i+1);
			return 1;
		}
	}

	/* test serpent with 256bit key */
	for (i = 0; i < table256_num; i++) {

		serpent_setkey(expkey, table256[i].key, 32);

		/* encrypt test */
		serpent_encrypt(check, table256[i].plain, expkey);
		if (memcmp(check, table256[i].enc, 16) != 0) {
			fprintf(stderr, "serpent-256 encrypt test %d failed\n", i+1);
			return 1;
		}

		/* 100x encrypt test */
		for (j = 0; j < 99; j++)
			serpent_encrypt(check, check, expkey);
		if (memcmp(check, table256[i].enc100, 16) != 0) {
			fprintf(stderr, "serpent-256 100x encrypt test %d failed\n", i+1);
			return 1;
		}

		/* 1000x encrypt test */
		for (j = 0; j < 900; j++)
			serpent_encrypt(check, check, expkey);
		if (memcmp(check, table256[i].enc1000, 16) != 0) {
			fprintf(stderr, "serpent-256 1000x encrypt test %d failed\n", i+1);
			return 1;
		}
	}

	return 0;
}
