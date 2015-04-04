#define _FILE_OFFSET_BITS	64

#include <sys/stat.h>

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
#include "readpass.h"
#include "pbkdf2-hmac-sha512.h"
#include "poly1305-serpent.h"
#include "ctr-serpent.h"
#include "defaults.h"


#define ITERATIONS	256000
#define PASSWD_SRC	"/dev/tty"

#define MODE_ENC	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define MODE_DEC	(S_IRUSR|S_IWUSR)

#define VERSION		"pre3.0-0"
#define FILEVER		7
#define PASSLEN		512
#define CHUNKLEN	(32*1024*1024)


struct venom {
	struct ctr_serpent		ctr;
	struct poly1305_serpent		mac;

	uint8_t				nonce[16];
};


struct config {
	int		 verbose;
	int		 force;

	uint64_t	 iterations;
	uint64_t	 chunklen;
	char		*passfn;	/* XXX const char? */
	int		 filemode;
};



struct header {
	char	 magic[5];
	uint16_t version;
	uint64_t iter;
	uint8_t	 nonce[16];
	uint64_t chunklen;
} __attribute__((packed));



void
printhex(const char *label, const uint8_t *vec, size_t n)
{
	int i;

        fprintf(stderr, "%s: ", label);
        if (n)
                for (i = 0; i < n; i++)
                        fprintf(stderr, "%02x", vec[i]);
        else
                fputc('-', stderr);

        fputc('\n', stderr);
}


void
printusage(FILE *fp)
{
	fprintf(fp, "Usage: venom [-hVedsvf] [-p <fn>] [-i <iter>] [-m <mode>] [<input>] [<output>]\n");
	fprintf(fp, "options:\n");
	fprintf(fp, "  -h\t\thelp\n");
	fprintf(fp, "  -V\t\tversion\n");
	fprintf(fp, "  -e\t\tencrypt\n");
	fprintf(fp, "  -d\t\tdecrypt (default)\n");
	fprintf(fp, "  -s\t\tshow file metadata\n");
	fprintf(fp, "  -v\t\tverbose\n");
	fprintf(fp, "  -f\t\tforce\n");
	fprintf(fp, "  -p <file>\tread password from <file> instead of %s\n", PASSWD_SRC);
	fprintf(fp, "  -i <n>\tset pbkdf2 iteration number to <n>\n");
	fprintf(fp, "  -m <mode>\tset file mode bits of output\n");
}

void
printversion(FILE *fp)
{
	fprintf(fp, "venom %s, file version: %d\n", VERSION, FILEVER);

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



void
crypto_init(struct venom *ctx, const uint8_t passwd[PASSLEN],
		const uint8_t nonce[16], uint64_t iter)
{
	uint8_t key[32+32]; /* 32 serpent ctr + 32 poly1305-serpent */

	pbkdf2_hmac_sha512(key, sizeof(key), passwd, PASSLEN, nonce, 16, iter);

	ctr_serpent_init(&ctx->ctr, key);
	ctr_serpent_nonce(&ctx->ctr, nonce);

	poly1305_serpent_setkey(&ctx->mac, key+32);

	/* copy nonce for chunk macs */
	memcpy(ctx->nonce, nonce, 16);
}


void
crypto_authdata(struct venom *ctx, const uint8_t *data, size_t len, uint8_t mac[16])
{
	int i;

	poly1305_serpent_nonce(&ctx->mac, ctx->nonce);
	poly1305_update(&ctx->mac.poly1305, data, len);
	poly1305_mac(&ctx->mac.poly1305, mac);

	/* advance mac nonce */
	for (i = 15; i >= 0 && ++ctx->nonce[i] == 0; i--);
}




/*
 * main functions
 */

int
encrypt(const char *inputfn, const char *outputfn, const struct config *conf)
{
	FILE *in = stdin;
	FILE *out = stdout;

	struct header header;
	uint8_t *buffer;
	size_t n;

	uint8_t passwd[PASSLEN];
	uint8_t random_nonce[16];

	struct venom crypto;

	int rc;


	/* allocate chunk buffer */
	buffer = malloc(conf->chunklen + 16);
	if (buffer == NULL) {
		warn("can't allocate memory");
		return 1;
	}


	/* open input file */
	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL) {
			warn("%s: can't open input file", inputfn);
			goto errout;
		}
	}


	/* read password */
	rc = read_pass_fn(conf->passfn, passwd, sizeof(passwd),
			"Password: ", "Confirm: ");
	if (rc == -1) 
		goto errout;	/* read_pass_fn is verbose, no extra warning needed */

	/* generate random nonce */
	if (secrand(random_nonce, 16) == -1) {
		warn("can't read random data");
		goto errout;
	}

	/* initialize crypto */
	if (conf->verbose > 1) {
		fprintf(stderr, "iterations: %" PRIu64 "\n", conf->iterations);
		printhex("nonce", random_nonce, 16);
	}
	crypto_init(&crypto, passwd, random_nonce, conf->iterations);


	/* open output file */
	if (strcmp(outputfn, "-") != 0) {
		out = fopen(outputfn, conf->force ? "w" : "wx");
		if (out == NULL) {
			warn("%s: can't open output file", outputfn);
			goto errout;
		}
	}


	/* create header */
	memcpy(header.magic, "VENOM", 5);
	header.version = htobe16(FILEVER);
	header.iter = htobe64(conf->iterations);
	memcpy(header.nonce, random_nonce, 16);
	header.chunklen = htobe64(conf->chunklen);
	memcpy(buffer, &header, sizeof(struct header));

	/* authenticate and write header */
	crypto_authdata(&crypto, buffer, sizeof(struct header),
			buffer+sizeof(struct header));
	if (fwrite(buffer, sizeof(struct header)+16, 1, out) != 1) {
		warn("%s: can't write to output file", outputfn);
		goto errout;
	}



	/* encryption loop XXX way may not dectect an error in our input stream */
	do {
		n = fread(buffer, 1, conf->chunklen, in);

		ctr_serpent_crypt(&crypto.ctr, buffer, buffer, n);
		crypto_authdata(&crypto, buffer, n, buffer+n);

		if (fwrite(buffer, 1, n+16, out) != n+16) {
			warn("%s: can't write to output file", outputfn);
			goto errout;
		}
	} while (n == conf->chunklen);


	/* XXX overwrite buffer? */
	free(buffer);

	if (in != stdin)
		fclose(in);
	if (out != stdout)
		fclose(out);

	return 0;

errout:
	/* XXX overwrite buffer? */
	free(buffer);
	if (in != stdin)
		fclose(in);
	if (out != stdout)
		fclose(out);
	return 1;
}


int
decrypt(const char *inputfn, const char *outputfn, const struct config *conf)
{
	FILE *in = stdin;
	FILE *out = stdout;
	
	struct header header;
	uint8_t *buffer = NULL;
	size_t n;
	uint8_t mac[16], check[16];
	uint64_t chunklen;

	uint8_t passwd[PASSLEN];

	struct venom crypto;

	int rc;



	/* open input file */
	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL) {
			warn("%s: can't open input file", inputfn);
			goto errout;
		}
	}
	

	/* read header */
	n = fread(&header, sizeof(struct header), 1, in);
	if (n != 1) {
		if (feof(in))
			warnx("%s: file too short, can't read header", inputfn);
		else
			warn("%s: can't read header", inputfn);
		goto errout;
	}

	if (memcmp(header.magic, "VENOM", 5) != 0) {
		warnx("%s: not a venom file", inputfn);
		goto errout;
	}
	if (be16toh(header.version) != FILEVER) {
		warnx("%s: unsupported file version: %u\n",
				inputfn, be16toh(header.version));
		goto errout;
	}



	/* read password */
	rc = read_pass_fn(conf->passfn, passwd, sizeof(passwd), "Password: ", NULL);
	if (rc == -1) 
		goto errout;	/* read_pass_fn is verbose */


	/* initialize cryptography */
	crypto_init(&crypto, passwd, header.nonce, be64toh(header.iter));


	/* read and check header mac */
	if (fread(mac, 1, 16, in) != 16) {
		if (feof(in))
			warnx("%s: file too short, header mac missing", inputfn);
		else
			warn("%s: can't read header mac", inputfn);

		goto errout;
	}
	crypto_authdata(&crypto, (uint8_t*)&header, sizeof(struct header), check);
	if (!ctiseq(mac, check, 16)) {
		warnx("%s: corrupt header or wrong password", inputfn);
		goto errout;
	}


	/* read chunk length from header and allocate buffer acordingly */
	chunklen = be64toh(header.chunklen);

	/* allocate chunk buffer */
	buffer = malloc(chunklen + 16);
	if (buffer == NULL) {
		warn("can't allocate memory");
		return 1;
	}


	/* open output file */
	if (strcmp(outputfn, "-") != 0) {
		out = fopen(outputfn, conf->force ? "w" : "wx");
		if (out == NULL) {
			warn("%s: can't open output file", outputfn);
			goto errout;
		}
	}

	/* decryption loop */
	do {
		n = fread(buffer, 1, chunklen+16, in);
		if (n < 16) {
			if (feof(in))
				warnx("%s: file too short, incomplete chunk", inputfn);
			else
				warn("%s: can't read from input file", inputfn);

			goto errout;
		}

		/* set n to the data length in this chunk */
		n -= 16;

		crypto_authdata(&crypto, buffer, n, check);
		if (!ctiseq(buffer+n, check, 16)) {
			warnx("%s: corrupt chunk, abort decryption", inputfn);
			goto errout;
		}

		ctr_serpent_crypt(&crypto.ctr, buffer, buffer, n);

		if (fwrite(buffer, 1, n, out) != n) {
			warn("%s: can't write to output file", outputfn);
			goto errout;
		}
	} while (n == chunklen);
	

	/* XXX overwrite buffer? */
	free(buffer);

	if (in != stdin)
		fclose(in);
	if (out != stdout)
		fclose(out);
	return 0;

errout:
	if (in != stdin)
		fclose(in);
	if (out != stdout)
		fclose(out);

	/* XXX overwrite buffer? */
	free(buffer);

	/* XXX delete output file */

	return 1;
}

int
show(const char *inputfn, const struct config *conf)
{
	FILE *in = stdin;

	struct header header;
	uint8_t *buffer = NULL;
	size_t n;


	uint64_t chunklen;

	uint8_t mac[16];

	if (strcmp(inputfn, "-") != 0) {
		in = fopen(inputfn, "r");
		if (in == NULL)
			err(1, "%s: can't open input file", inputfn);
	}

	/* read header */
	n = fread(&header, sizeof(struct header), 1, in);
	if (n != 1) {
		if (feof(in))
			warnx("%s: file too short, can't read header", inputfn);
		else
			warn("%s: can't read header", inputfn);
		goto errout;
	}

	if (memcmp(header.magic, "VENOM", 5) != 0) {
		warnx("%s: not a venom file", inputfn);
		goto errout;
	}


	/* 
	 * XXX this function should write to stdout
	 */

	fprintf(stderr, "venom file, version: %u\n", be16toh(header.version));

	if (be16toh(header.version) != FILEVER) {
		warnx("%s: unsupported file version: %u",
			inputfn, be16toh(header.version));
		goto errout;
	}

	chunklen = be64toh(header.chunklen);

	/* show key param values */
	fprintf(stderr, "iterations: %" PRIu64 "\n", be64toh(header.iter));
	fprintf(stderr, "chunk length: %" PRIu64 "\n", chunklen);
	printhex("nonce", header.nonce, 16);

	if (fread(mac, 1, 16, in) != 16) {
		if (feof(in))
			warnx("%s: file too short, can't read header mac", inputfn);
		else
			warn("%s: can't read header mac", inputfn);
		goto errout;
	}

	printhex("header mac", mac, 16);

	if (conf->verbose > 0) {
		buffer = malloc(chunklen+16);
		if (buffer == NULL) {
			warn("can't allocate memory");
			goto errout;
		}

		do {

			n = fread(buffer, 1, chunklen+16, in);
			if (n < 16) {
				if (feof(in))
					warnx("%s: file too short, can't read chunk", inputfn);
				else
					warn("%s: error reading chunk", inputfn);
				goto errout;
			}

			n -= 16;

			printhex("chunk mac", buffer+n, 16);
		} while (n == chunklen);
	}


	free(buffer);
	if (in != stdin)
		fclose(in);

	return 0;

errout:
	free(buffer);
	if (in != stdin)
		fclose(in);

	return 1;
}


int
main(int argc, char *argv[])
{
	char *inputfn = "-";
	char *outputfn = "-";

	struct config conf;
	char mode = 'd';
	int rc;
	int rval = 1;

	/* set default config values */
	conf.verbose = 0;
	conf.force = 0;
	conf.iterations = ITERATIONS;
	conf.chunklen = CHUNKLEN;
	conf.passfn = PASSWD_SRC;
	conf.filemode = -1;


	/* parse parameters */
	while ((rc = getopt(argc, argv, "hVedsvfi:m:p:")) != -1) {
		switch (rc) {

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

		case 'm':
			conf.filemode = strtol(optarg, NULL, 8);
			if (conf.filemode == LONG_MIN || conf.filemode == LONG_MAX)
				errx(1, "illegal mode: %d", conf.filemode);
			break;

		/* main modes */
		case 'h':
			printusage(stdout);
			exit(0);
		case 'V':
			printversion(stdout);
			exit(0);

		case 'e':
		case 'd':
		case 's':
			mode = rc;
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
		errx(1, "illegal number of pbkdf2 iterations: %ld",
				conf.iterations);

	if (conf.chunklen < sizeof(struct header))
		errx(1, "chunk size too small: %ld", conf.chunklen);

	/* early warning if output file already exists... */
	if (strcmp(outputfn, "-") != 0) {
		if (!conf.force && exists(outputfn))
			errx(1, "%s: output file already exists, use -f to overwrite", outputfn);
	}

	/* XXX lock memory */


	/* now do our job */
	switch (mode) {
	case 'e':
		rval = encrypt(inputfn, outputfn, &conf);
		break;
	case 'd':
		rval = decrypt(inputfn, outputfn, &conf);
		break;
	case 's':
		rval = show(inputfn, &conf);
		break;
	}
		 
	/* XXX cleanup stack */

	return rval;
}
