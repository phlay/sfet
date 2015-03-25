#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "printvec.h"
#include "poly1305.h"


#define MAXLEN	2048

const struct {
	uint8_t		msg[MAXLEN];
	uint8_t		r[16];
	uint8_t		encno[16];
	uint8_t		mac[16];
} table[] = {
	#include "poly1305-table.h"
};

const int table_num = sizeof(table) / sizeof(table[0]);


int main()
{
	struct poly1305 poly;
	uint8_t check[16];
	int i;

	if (table_num > MAXLEN) {
		fprintf(stderr, "buffer too small\n");
		return 1;
	}


	for (i = 0; i < table_num; i++) {
		poly1305_init(&poly, table[i].r);
		poly1305_update(&poly, table[i].msg, i);
		poly1305_mac(&poly, table[i].encno, check);

		if (memcmp(check, table[i].mac, 16) != 0) {
			fprintf(stderr, "poly1305-selftest: test number %d failed\n", i+1);
			printvec("is", check, 16);
			printvec("should", table[i].mac, 16);
			return 1;
		}
	}

	return 0;
}
