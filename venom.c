/* venom - file crypting utility using serpent in eax mode.
 *
 * a venom file consists of a header (see struct header below), the encrypted
 * user data and finally a 16 byte tag authenticating header and encrypted data.
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#define _FILE_OFFSET_BITS	64


#include <inttypes.h>
#include <stdint.h>
#include <limits.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <errno.h>
#include <err.h>

#include "defaults.h"

#include "utils.h"
#include "eax-serpent.h"
#include "pbkdf2-hmac-sha512.h"
#include "readpass.h"


#define VERSION		6
#define PASSLEN		512


struct keyparam {
	uint8_t		passwd[PASSLEN];
	uint8_t		nonce[DEF_NONCELEN];
	uint64_t	iter;
	uint8_t		pwcheck[4];
};



/* printhex - simple function to print binary arrays in hex.
 */
static void
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




int
read_header(FILE *in, struct keyparam *kp)
{
	uint8_t magic[5];
	uint16_t version;
	uint64_t iter;
	size_t n;

	/* is this really a file from us? */
	n = fread(magic, sizeof(magic), 1, in);
	if (n != 1) {
		warnx("can't read magic");
		return -1;
	}
	if (memcmp(magic, "VENOM", 5) != 0) {
		warnx("not a venom encrypted file");
		return -1;
	}


	/* check version */
	n = fread(&version, sizeof(version), 1, in);
	if (n != 1) {
		warnx("can't read version from file");
		return -1;
	}
	if (be16toh(version) != VERSION) {
		warnx("wrong file version %d (need %d)",
		      be16toh(version), VERSION);
		return -1;
	}

	/* read iteration counter for pbkdf2 */
	n = fread(&iter, sizeof(iter), 1, in);
	if (n != 1) {
		warnx("can't read pbkdf2 iteration number");
		return -1;
	}
	kp->iter = be64toh(iter);


	/* read nonce */
	n = fread(kp->nonce, sizeof(kp->nonce), 1, in);
	if (n != 1) {
		warnx("can't read nonce");
		return -1;
	}

	/* read pwcheck */
	n = fread(kp->pwcheck, sizeof(kp->pwcheck), 1, in);
	if (n != 1) {
		warnx("can't read pwcheck");
		return -1;
	}

	return 0;
}


int
write_header(FILE *out, const struct keyparam *kp)
{
	uint16_t version = htobe16(VERSION);
	uint64_t iter = htobe64(kp->iter);
	size_t n;

	/* write header to output */
	n = fwrite("VENOM", 5, 1, out);
	if (n != 1) {
		warn("error writing magic");
		return -1;
	}

	n = fwrite(&version, sizeof(version), 1, out);
	if (n != 1) {
		warn("error writing file version");
		return -1;
	}

	n = fwrite(&iter, sizeof(iter), 1, out);
	if (n != 1) {
		warn("error writing iteration count");
		return -1;
	}

	n = fwrite(kp->nonce, sizeof(kp->nonce), 1, out);
	if (n != 1) {
		warn("error writing nonce");
		return -1;
	}

	n = fwrite(kp->pwcheck, sizeof(kp->pwcheck), 1, out);
	if (n != 1) {
		warn("error writing password check");
		return -1;
	}

	return 0;
}




int
init_cipher(eax_serpent_t *C, struct keyparam *kp, int enc)
{
	uint8_t key[SERPENT_MAX_KEY_SIZE];
	uint8_t N[DEF_NONCELEN];
	uint8_t tag[16];

	/*
	 * we need three nonces
	 *   1) pbkdf2 key setup
	 *   2) hash for password check
	 *   3) main encryption/decryption
	 *
	 * first nonce is taken directly from key parameters. after
	 * that the first byte of the nonce is incremented, to get a new nonce.
	 */

	/* copy nonce */
	memcpy(N, kp->nonce, DEF_NONCELEN);

	/* derive encryption key and setup eax-serpent cipher */
	pbkdf2_hmac_sha512(key, sizeof(key), kp->passwd, PASSLEN,
			N, DEF_NONCELEN, kp->iter);

	eax_serpent_init(C, key, sizeof(key));


	/* next nonce for password check */
	N[0]++;
	eax_serpent_nonce(C, N, DEF_NONCELEN);

	/* now hash magic and (original) nonce for password check */
	eax_serpent_header(C, (uint8_t*)"VENOM", 5);
	eax_serpent_header(C, kp->nonce, DEF_NONCELEN);
	eax_serpent_tag(C, tag);

	/* install next nonce to make cipher ready to encrypt/decrypt */
	N[0]++;
	eax_serpent_nonce(C, N, DEF_NONCELEN);


	if (enc)
		memcpy(kp->pwcheck, tag, 4);
	else if (memcmp(tag, kp->pwcheck, 4) != 0)
		return -1;

	return 0;
}



int
encrypt_stream(FILE *in, FILE *out, eax_serpent_t *C, int verbose)
{
	uint8_t buffer[DEF_BUFSIZE];
	uint8_t tag[16];
	size_t n;

	/* encryption loop */
	while ((n = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE, in)) != 0) {
		eax_serpent_encrypt(C, buffer, buffer, n);

		if (fwrite(buffer, sizeof(uint8_t), n, out) != n) {
			warn("can't write to output file");
			return -1;
		}
	}
	if (ferror(in)) {
		warn("can't read from input file");
		return -1;
	}

	/* write final tag */
	eax_serpent_tag(C, tag);
	if (verbose > 0)
		printhex("tag", tag, 16);

	if (fwrite(tag, sizeof(uint8_t), 16, out) != 16) {
		warn("can't write tag to output");
		return -1;
	}

	return 0;
}


int
decrypt_stream(FILE *in, FILE *out, eax_serpent_t *C, int verbose)
{
	uint8_t buffer[DEF_BUFSIZE+16];
	uint8_t tag[16];
	size_t n;

	/* the decryption-loop is more complicated because we have
	 * to look out for the final tag. we do that by maintaining a
	 * tag-buffer behind our normal read buffer.
	 */

	n = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE+16, in);
	if (n < 16) {
		if (ferror(in))
			warn("can't read from input file");
		else
			warnx("input file is too short");

		return -1;
	}

	/* subtract 16, because this could already be the final tag */
	n -= 16;

	/* main loop: buffer always holding n+16 bytes of data */
	for (;;) {
		eax_serpent_decrypt(C, buffer, buffer, n);
		if (fwrite(buffer, sizeof(uint8_t), n, out) != n) {
			warn("can't write to output file");
			return -1;
		}

		/* copy tag-buffer to beginning */
		memmove(buffer, buffer+n, 16);
		if (n < DEF_BUFSIZE)
			break;

		/* we are not done: read next chunk of data behind the 16 byte
		 * we still have in our buffer
		 */
		n = fread(buffer+16, sizeof(uint8_t), DEF_BUFSIZE, in);
	}
	if (ferror(in)) {
		warn("can't read from input file");
		return -1;
	}

	/* calculate and check eax-tag */
	eax_serpent_tag(C, tag);
	if (verbose > 0)
		printhex("tag", tag, 16);

	if (memcmp(tag, buffer, 16) != 0) {
		warnx("mac check failed: encrypted file is corrupted!");
		if (verbose > 0)
			printhex("file tag", buffer+n, 16);

		return -1;
	}

	return 0;
}



void
usage()
{
	fprintf(stderr, "Usage: venom [-edsvf] [-i <iter>] [-m <mode>] [<input>] [<output>]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -e\t\tencrypt\n");
	fprintf(stderr, "  -d\t\tdecrypt\n");
	fprintf(stderr, "  -s\t\tshow file metadata\n");
	fprintf(stderr, "  -v\t\tverbose\n");
	fprintf(stderr, "  -f\t\tforce\n");
	fprintf(stderr, "  -i n\t\tset pbkdf2 iteration number to n\n");
	fprintf(stderr, "  -m <mode>\tset file mode bits of output\n");
}


int
main(int argc, char *argv[])
{
	char mode = 0;

	int verbose = 0;
	int force = 0;

	char *inputfn = "-";
	char *outputfn = "-";

	FILE *in, *out;
	char tmpoutfn[PATH_MAX];
	int outmode = -1;

	struct keyparam keyparam;
	eax_serpent_t cipher;

	int rc;


	/*
	 * fill in default parameter
	 */

	keyparam.iter = DEF_ITERATION;


	/*
	 * parse arguments
	 */

	while ((rc = getopt(argc, argv, "hedsvfi:m:")) != -1) {
		switch (rc) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			verbose++;
			break;

		case 'f':
			force = 1;
			break;

		case 'i':
			keyparam.iter = atoll(optarg);
			break;

		case 'm':
			outmode = strtol(optarg, NULL, 8);
			if (outmode == LONG_MIN || outmode == LONG_MAX)
				errx(1, "illegal mode: %s", optarg);
			break;


		case 'e':
		case 'd':
		case 's':
			mode = rc;
			break;

		default:
			usage();
			exit(1);
		}
	}

	/* check configuration parameters */
	if (keyparam.iter < 1024)
		errx(1, "illegal pkbdf2 iteration number: %" PRIu64, keyparam.iter);

	if (outmode == -1) {
		if (mode == 'e')
			outmode = DEF_MODE_ENC;
		else if (mode == 'd')
			outmode = DEF_MODE_DEC;
	}

	if (mode == 0) {
		usage();
		exit(1);
	}

	/* positional parameters are interpreted as input and output file */
	argc -= optind;
	argv += optind;

	if (argc > 0)
		inputfn = argv[0];
	if (argc > 1)
		outputfn = argv[1];


	/* 
	 * open input file 
	 */
	if (strcmp(inputfn, "-") == 0)
		in = stdin;
	else {
		in = fopen(inputfn, "r");
		if (in == NULL)
			err(1, "%s: can't open input file", inputfn);
	}

	/* read & check header, if we expect an encrypted input */
	if (mode != 'e') {
		if (read_header(in, &keyparam) == -1) {
			/* error reading input file? */
			if (ferror(in))
				err(1, "%s: can't read from file", inputfn);
			exit(1);
		}
	}


	/*
	 * handle show-meta-data-mode (-s)
	 */
	if (mode == 's') {
		uint8_t tag[16];

		/* show key param values */
		fprintf(stderr, "iterations: %" PRIu64 "\n", keyparam.iter);
		printhex("nonce", keyparam.nonce, DEF_NONCELEN);
		printhex("pwcheck", keyparam.pwcheck, sizeof(keyparam.pwcheck));

		/* seek file and show tag */
		if (fseek(in, -16, SEEK_END) == -1)
			err(1, "%s: can't seek file", inputfn);
		if (fread(tag, sizeof(tag), 1, in) != 1)
			err(1, "can't read tag");

		printhex("tag", tag, 16);

		return 0;
	}


	/* 
	 * open output file
	 */
	if (strcmp(outputfn, "-") == 0)
		out = stdout;
	else {
		if (!force && exists(outputfn))
			errx(1, "%s: output file already exists, use -f to overwrite", outputfn);

		out = opentemp(tmpoutfn, outputfn, outmode);
		if (out == NULL)
			errx(1, "can't open temp file");
	}

	/* read password
	 *
	 * read_pass_tty returns the length of the password, but we ignore that
	 * and use the feature that the password will be padded to fit in the
	 * hole buffer. that way we could use the hole buffer as a fixed size
	 * password.
	 */

	rc = read_pass_tty(keyparam.passwd, sizeof(keyparam.passwd), "Password",
			mode == 'e' ? "Confirm" : NULL);
	if (rc == -1)
		errx(1, "can't read password");


	/* generate nonce */
	if (mode == 'e') {
		rc = secrand(keyparam.nonce, sizeof(keyparam.nonce));
		if (rc == -1)
			errx(1, "can't read random");
	}


	/* display metadata if verbosity is at least 2 */
	if (verbose > 1) {
		fprintf(stderr, "iterations: %" PRIu64 "\n", keyparam.iter);
		printhex("nonce", keyparam.nonce, DEF_NONCELEN);
	}

	/* init encryption */
	if (init_cipher(&cipher, &keyparam, mode == 'e' ? 1 : 0) == -1)
		errx(1, "wrong password");


	/*
	 * finally encrypt/decrypt
	 */
	switch (mode) {
	case 'e':
		rc = write_header(out, &keyparam);
		if (rc == -1)
			exit(1);
		rc = encrypt_stream(in, out, &cipher, verbose);
		if (rc == -1)
			exit(1);
		break;
	case 'd':
		rc = decrypt_stream(in, out, &cipher, verbose);
		if (rc == -1)
			exit(1);
		break;
	default:
		errx(1, "oops, internal error");
	}


	/*
	 * handle output file, if not stdout
	 */
	if (out != stdout) {
		/* if using force, unlink outputfn */
		if (force && exists(outputfn))
			if (unlink(outputfn) == -1)
				err(1, "%s: can't unlink destination", outputfn);

		/* link anonymous temp-file into place */
		rc = linkat(AT_FDCWD, tmpoutfn, AT_FDCWD, outputfn, AT_SYMLINK_FOLLOW);
		if (rc == -1)
			err(1, "%s: can't link output into place", tmpoutfn);
	}


	/* close files */
	fclose(in);
	fclose(out);

	return 0;
}
