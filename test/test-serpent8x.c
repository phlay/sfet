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
	uint8_t check[8*16];
	int i, j, k;

	/* test serpent with 128key key */
	for (i = 0; i < table128_num; i++) {
		serpent_setkey(expkey, table128[i].key, 16);

		/* prepare check buffer */
		for (k = 0; k < 8; k++)
			memcpy(check + k*16, table128[i].plain, 16);

		/* encryption test */
		serpent8x_encrypt(check, check, expkey);

		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table128[i].enc, 16) != 0) {
				fprintf(stderr, "serpent-128 encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}


		/* encrypt 99 times more */
		for (j = 0; j < 99; j++)
			serpent8x_encrypt(check, check, expkey);

		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table128[i].enc100, 16) != 0) {
				fprintf(stderr, "serpent-128 100x encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}

		/* encrypt 900 times more */
		for (j = 0; j < 900; j++)
			serpent8x_encrypt(check, check, expkey);

		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table128[i].enc1000, 16) != 0) {
				fprintf(stderr, "serpent-128 1000x encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}
	}

	/* test serpent with 256bit key */
	for (i = 0; i < table256_num; i++) {

		serpent_setkey(expkey, table256[i].key, 32);

		/* prepare encryption buffer */
		for (k = 0; k < 8; k++)
			memcpy(check + k*16, table256[i].plain, 16);

		/* encrypt test */
		serpent8x_encrypt(check, check, expkey);
		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table256[i].enc, 16) != 0) {
				fprintf(stderr, "serpent-256 encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}

		/* 100x encrypt test */
		for (j = 0; j < 99; j++)
			serpent8x_encrypt(check, check, expkey);
		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table256[i].enc100, 16) != 0) {
				fprintf(stderr, "serpent-256 100x encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}

		/* 1000x encrypt test */
		for (j = 0; j < 900; j++)
			serpent8x_encrypt(check, check, expkey);
		for (k = 0; k < 8; k++) {
			if (memcmp(check + k*16, table256[i].enc1000, 16) != 0) {
				fprintf(stderr, "serpent-256 1000x encrypt test %d block %d failed\n",
						i+1, k);
				return 1;
			}
		}
	}

	return 0;
}
