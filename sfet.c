#ifdef __linux
  #define _FILE_OFFSET_BITS	64
  #include <sys/prctl.h>
#endif

#include <sys/resource.h>
#include <sys/mman.h>

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <endian.h>
#include <err.h>

#include "utils.h"
#include "cleanup.h"
#include "buffer.h"
#include "burnstack.h"
#include "readpass.h"
#include "pbkdf2-hmac-sha512.h"
#include "poly1305-serpent.h"
#include "ctr-serpent.h"



#define ITERATIONS	256000
#define PASSWD_SRC	"/dev/tty"

#define VERSION		"pre3.0-0"
#define FILEVER		8
#define PASSLEN		512
#define CHUNKLEN	(32*1024*1024)



struct config {
	int		 verbose;
	int		 force;

	uint64_t	 iterations;
	uint64_t	 chunklen;
	const char	*passfn;
};

struct header {
	char	 magic[4];
	uint16_t version;
	uint64_t iter;
	uint8_t	 nonce[16];
	uint64_t chunklen;
} __attribute__((packed));



static void
printhex(FILE *fp, const uint8_t *vec, size_t n)
{
	int i;

        if (n > 0) {
                for (i = 0; i < n; i++)
                        fprintf(fp, "%02x", vec[i]);
	} else
                fputc('-', fp);

        fputc('\n', fp);
}


static void
printusage(FILE *fp)
{
	fprintf(fp, "decrypt:\tsfet [-d] [-vf] [-p <fn>] [<input>] [<output>]\n");
	fprintf(fp, "encrypt:\tsfet -e [-vf] [-p <fn>] [-i <iter>] [-c <length>] [<input>] [<output>]\n");
	fprintf(fp, "show metadata:\tsfet -s [-v] [<input>]\n");
	fprintf(fp, "\n");
	fprintf(fp, "options:\n");
	fprintf(fp, "  -v\t\tincrease verbosity level\n");
	fprintf(fp, "  -f\t\toverwrite outputfile, if it already exists\n");
	fprintf(fp, "  -p <file>\tread password from <file> instead of %s\n", PASSWD_SRC);
	fprintf(fp, "  -i <n>\tset pbkdf2 iteration number to <n>, encryption only\n");
	fprintf(fp, "  -c <length>\tset chunk size to <length>, encryption only\n");
	fprintf(fp, "  -V\t\tshow version\n");
	fprintf(fp, "  -h\t\tshow this help message\n");
}

static void
printversion(FILE *fp)
{
	fprintf(fp, "sfet %s, file version: %d\n", VERSION, FILEVER);

#if defined(USE_ASM_X86_64) || defined(USE_ASM_AVX)
	fprintf(fp, "build with: ");

#ifdef USE_ASM_X86_64
	fprintf(fp, "ASM-X86-64 ");
#endif
#ifdef USE_ASM_AVX
	fprintf(fp, "AVX ");
#endif
	fprintf(fp, "\n");
#endif
}

static int
parse_chunklen(uint64_t *out, const char *str)
{
	char *endp;
	long long int n;

	n = strtoll(str, &endp, 10);
	if (n <= 0 || n == LONG_MAX)
		return -1;

	switch (*endp) {
	case '\0':
		*out = n;
		break;
	case 'k': case 'K':
		*out = (uint64_t)n * 1024;
		break;
	case 'm': case 'M':
		*out = (uint64_t)n * 1024 * 1024;
		break;
	case 'g': case 'G':
		*out = (uint64_t)n * 1024 * 1024 * 1024;
		break;
	default:
		return -1;
	}

	return 0;
}


static inline void
next_nonce(uint8_t nonce[16])
{
	int i;
	for (i = 15; i >= 0 && ++nonce[i] == 0; i--);
}



/*
 * main functions
 */

static int
encrypt(const char *inputfn, const char *outputfn, const struct config *conf)
{
	cu_fclose FILE *in = stdin;
	cu_fclose FILE *out = stdout;

	cu_freebuffer struct buffer *buffer = NULL;

	struct header header;
	size_t n;

	uint8_t passwd[PASSLEN];
	uint8_t key[32+32]; /* 32 serpent ctr + 32 poly1305-serpent */
	uint8_t nonce[16];

	struct ctr_serpent ctrctx;
	struct poly1305_serpent polyctx;


	/* open input file */
	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL) {
			warn("%s: can't open input file", inputfn);
			return 1;
		}
	}

	/* read password (read_pass_fn is verbose) */
	if (read_pass_fn(conf->passfn, passwd, sizeof(passwd),
			"Password: ", "Confirm: ") == -1)
		return 1;

	/* initialize nonce with random data */
	if (secrand(nonce, 16) == -1) {
		warn("can't read random data");
		return 1;
	}

	/* initialize crypto */
	if (conf->verbose > 0) {
		fprintf(stderr, "chunk length: %" PRIu64 "\n", conf->chunklen);
		fprintf(stderr, "iterations: %" PRIu64 "\n", conf->iterations);
		fprintf(stderr, "nonce: ");
		printhex(stderr, nonce, 16);
	}

	pbkdf2_hmac_sha512(key, sizeof(key), passwd, PASSLEN, nonce, 16, conf->iterations);

	ctr_serpent_init(&ctrctx, key);
	ctr_serpent_nonce(&ctrctx, nonce);
	poly1305_serpent_setkey(&polyctx, key+32);


	/* allocate chunk buffer */
	buffer = buffer_alloc(conf->chunklen + 16);
	if (buffer == NULL) {
		warn("can't allocate memory");
		return 1;
	}


	/* open output file */
	if (strcmp(outputfn, "-") != 0) {
		out = fopen(outputfn, conf->force ? "w" : "wx");
		if (out == NULL) {
			warn("%s: can't open output file", outputfn);
			return 1;
		}
	}


	/* create header */
	memcpy(header.magic, "SFET", 4);
	header.version = htobe16(FILEVER);
	header.iter = htobe64(conf->iterations);
	memcpy(header.nonce, nonce, 16);
	header.chunklen = htobe64(conf->chunklen);
	memcpy(buffer->data, &header, sizeof(struct header));

	/* authenticate and write header */
	poly1305_serpent_authdata(&polyctx, buffer->data, sizeof(struct header),
			nonce, buffer->data+sizeof(struct header));
	next_nonce(nonce);

	if (fwrite(buffer->data, sizeof(struct header)+16, 1, out) != 1) {
		warn("%s: can't write to output file", outputfn);
		return 1;
	}

	/* encryption loop */
	do {
		n = fread(buffer->data, 1, conf->chunklen, in);

		ctr_serpent_crypt(&ctrctx, buffer->data, buffer->data, n);

		poly1305_serpent_authdata(&polyctx, buffer->data, n, nonce, buffer->data+n);
		next_nonce(nonce);

		if (fwrite(buffer->data, 1, n+16, out) != n+16) {
			warn("%s: can't write to output file", outputfn);
			return 1;
		}
	} while (n == conf->chunklen);

	/* check for reading error */
	if (ferror(in)) {
		warn("%s: error reading file", inputfn);
		return 1;
	}

	return 0;
}


static int
decrypt(const char *inputfn, const char *outputfn, const struct config *conf)
{
	cu_fclose FILE *in = stdin;
	cu_fclose FILE *out = stdout;
	
	cu_freebuffer struct buffer *buffer = NULL;

	struct header header;
	size_t n;
	uint8_t mac[16], check[16];
	uint64_t chunklen;

	uint8_t passwd[PASSLEN];
	uint8_t key[32+32]; /* 32 serpent ctr + 32 poly1305-serpent */
	uint8_t nonce[16];

	struct ctr_serpent ctrctx;
	struct poly1305_serpent polyctx;


	/* open input file */
	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL) {
			warn("%s: can't open input file", inputfn);
			return 1;
		}
	}

	/* read header */
	n = fread(&header, sizeof(struct header), 1, in);
	if (n != 1) {
		if (feof(in))
			warnx("%s: file too short, can't read header", inputfn);
		else
			warn("%s: can't read header", inputfn);
		return 1;
	}

	if (memcmp(header.magic, "SFET", 4) != 0) {
		warnx("%s: not a sfet file", inputfn);
		return 1;
	}
	if (be16toh(header.version) != FILEVER) {
		warnx("%s: unsupported file version: %u\n",
				inputfn, be16toh(header.version));
		return 1;
	}

	memcpy(nonce, header.nonce, 16);
	chunklen = be64toh(header.chunklen);


	/* read password */
	if (read_pass_fn(conf->passfn, passwd, sizeof(passwd),
			"Password: ", NULL) == -1)
		return 1;	/* read_pass_fn is verbose */


	/* initialize cryptography */
	if (conf->verbose > 0) {
		fprintf(stderr, "chunk length: %" PRIu64 "\n", chunklen);
		fprintf(stderr, "iterations: %" PRIu64 "\n", be64toh(header.iter));
		fprintf(stderr, "nonce: ");
		printhex(stderr, nonce, 16);
	}

	pbkdf2_hmac_sha512(key, sizeof(key), passwd, PASSLEN, nonce, 16, be64toh(header.iter));

	ctr_serpent_init(&ctrctx, key);
	ctr_serpent_nonce(&ctrctx, nonce);
	poly1305_serpent_setkey(&polyctx, key+32);


	/* read and check header mac */
	if (fread(mac, 1, 16, in) != 16) {
		if (feof(in))
			warnx("%s: file too short, header mac missing", inputfn);
		else
			warn("%s: can't read header mac", inputfn);

		return 1;
	}
	poly1305_serpent_authdata(&polyctx,
			(uint8_t*)&header, sizeof(struct header),
			nonce, check);
	next_nonce(nonce);
	if (!ctiseq(mac, check, 16)) {
		warnx("%s: corrupt header or wrong password", inputfn);
		return 1;
	}


	/* allocate chunk buffer */
	buffer = buffer_alloc(chunklen + 16);
	if (buffer == NULL) {
		warn("can't allocate memory");
		return 1;
	}


	/* open output file */
	if (strcmp(outputfn, "-") != 0) {
		out = fopen(outputfn, conf->force ? "w" : "wx");
		if (out == NULL) {
			warn("%s: can't open output file", outputfn);
			return 1;
		}
	}

	/* decryption loop */
	do {
		n = fread(buffer->data, 1, chunklen+16, in);
		if (n < 16) {
			/* is this an error or is the file damaged? */
			if (ferror(in))
				warn("%s: can't read from input file", inputfn);
			else
				warnx("%s: incomplete chunk, file is damaged", inputfn);

			return 1;
		}

		/* set n to the data length in this chunk */
		n -= 16;

		poly1305_serpent_authdata(&polyctx, buffer->data, n, nonce, check);
		next_nonce(nonce);
		if (!ctiseq(buffer->data+n, check, 16)) {
			warnx("%s: WARNING, file was modified!", inputfn);
			return 1;
		}

		ctr_serpent_crypt(&ctrctx, buffer->data, buffer->data, n);

		if (fwrite(buffer->data, 1, n, out) != n) {
			warn("%s: can't write to output file", outputfn);
			return 1;
		}
	} while (n == chunklen);

	/* check for input error */
	if (ferror(in)) {
		warn("%s: can't read from input file", inputfn);
		return 1;
	}
	
	return 0;
}

int
show(const char *inputfn, const struct config *conf)
{
	cu_fclose FILE *in = stdin;

	cu_freebuffer struct buffer *buffer = NULL;

	struct header header;
	size_t n;

	uint64_t chunklen;

	uint8_t mac[16];

	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL) {
			warn("%s: can't open input file", inputfn);
			return 1;
		}
	}

	/* read header */
	n = fread(&header, sizeof(struct header), 1, in);
	if (n != 1) {
		if (feof(in))
			warnx("%s: file too short, can't read header", inputfn);
		else
			warn("%s: can't read header", inputfn);
		return 1;
	}

	if (memcmp(header.magic, "SFET", 4) != 0) {
		warnx("%s: not a sfet file", inputfn);
		return 1;
	}


	printf("sfet file, version: %u\n", be16toh(header.version));

	if (be16toh(header.version) != FILEVER) {
		warnx("%s: unsupported file version: %u",
			inputfn, be16toh(header.version));
		return 1;
	}

	chunklen = be64toh(header.chunklen);

	/* show key param values */
	printf("iterations: %" PRIu64 "\n", be64toh(header.iter));
	printf("chunk length: %" PRIu64 "\n", chunklen);
	printf("nonce: ");
	printhex(stdout, header.nonce, 16);

	if (fread(mac, 1, 16, in) != 16) {
		if (feof(in))
			warnx("%s: file too short, can't read header mac", inputfn);
		else
			warn("%s: can't read header mac", inputfn);
		return 1;
	}

	printf("header mac: ");
	printhex(stdout, mac, 16);

	if (conf->verbose > 0) {
		buffer = buffer_alloc(chunklen+16);
		if (buffer == NULL) {
			warn("can't allocate memory");
			return 1;
		}

		do {
			n = fread(buffer->data, 1, chunklen+16, in);
			if (n < 16) {
				if (feof(in))
					warnx("%s: file too short, can't read chunk", inputfn);
				else
					warn("%s: error reading chunk", inputfn);
				return 1;
			}

			n -= 16;

			printf("chunk mac: ");
			printhex(stdout, buffer->data+n, 16);
		} while (n == chunklen);

		if (ferror(in)) {
			warn("%s: can't read input file", inputfn);
			return 1;
		}
	}


	return 0;
}


int
main(int argc, char *argv[])
{
	const char *inputfn = "-";
	const char *outputfn = "-";

	struct config conf;
	int option;
	int rval = 1;

	enum {
		MODE_ENCRYPT,
		MODE_DECRYPT,
		MODE_SHOW,
	} mode;


	/*
	 * set core limit to 0, which disables core dumps on most unix
	 * systems.
	 *
	 * please note: this does not work for linux, if a pipe is being used
	 * for core_pattern (like systemd-coredump in a typical systemd setup).
	 * a hack wourd be to set the core limit to 1, but we use the
	 * 'official' method with prctl on linux, see below.
	 */
	if (setrlimit(RLIMIT_CORE, &(struct rlimit){0, 0}) == -1)
		err(1, "cat't disable core dumps via setrlimit()");

#ifdef __linux
	/* disable core dumps under linux */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1)
		err(1, "can't disable core dumps");
#endif

	/* lock memory */
	if (mlockall(MCL_CURRENT|MCL_FUTURE) == -1)
		err(1, "can't lock memory");

	/* set default config values */
	conf.verbose = 0;
	conf.force = 0;
	conf.iterations = ITERATIONS;
	conf.chunklen = CHUNKLEN;
	conf.passfn = PASSWD_SRC;

	mode = MODE_DECRYPT;


	/* parse parameters */
	while ((option = getopt(argc, argv, "hVedsvfi:c:p:")) != -1) {
		switch (option) {

		/* options */
		case 'v':
			conf.verbose++;
			break;

		case 'f':
			conf.force = 1;
			break;

		case 'i':
			conf.iterations = atoll(optarg);
			break;

		case 'p':
			conf.passfn = optarg;
			break;

		case 'c':
			if (parse_chunklen(&conf.chunklen, optarg) == -1)
				errx(1, "illegal chunk length: %s", optarg);
			break;

		/* main modes */
		case 'h':
			printusage(stdout);
			exit(0);
		case 'V':
			printversion(stdout);
			exit(0);

		case 'e':
			mode = MODE_ENCRYPT;
			break;

		case 'd':
			mode = MODE_DECRYPT;
			break;

		case 's':
			mode = MODE_SHOW;
			break;

		default:
			printusage(stderr);
			printf("version: %s, fileversion: %d\n", VERSION, FILEVER);
			exit(1);
		}
	}
	argc -= optind;
	argv += optind;


	/* check parameter */
	if (argc > 0)
		inputfn = argv[0];
	if (argc > 1)
		outputfn = argv[1];

	if (conf.iterations < 1024)
		errx(1, "illegal number of pbkdf2 iterations: %" PRIu64,
				conf.iterations);

	if (conf.chunklen < sizeof(struct header))
		errx(1, "chunk size too small: %" PRIu64, conf.chunklen);

	/* early warning if output file already exists... */
	if (strcmp(outputfn, "-") != 0) {
		if (!conf.force && exists(outputfn))
			errx(1, "%s: output file already exists, use -f to overwrite", outputfn);
	}

	/* now do our job */
	switch (mode) {
	case MODE_ENCRYPT:
		rval = encrypt(inputfn, outputfn, &conf);
		break;
	case MODE_DECRYPT:
		rval = decrypt(inputfn, outputfn, &conf);
		break;
	case MODE_SHOW:
		rval = show(inputfn, &conf);
		break;
	}
		 
	/* cleanup stack */
	burnstack(64);

	return rval;
}
