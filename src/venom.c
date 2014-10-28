/* venom - file crypting utility using serpent in eax mode
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


#include <stdint.h>
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include <err.h>

#include "defaults.h"

#include "utils.h"
#include "eax-serpent.h"
#include "pbkdf2-hmac-sha512.h"
#include "readpass.h"


#define VERSION		6


/*
 * header definition for a venom file
 */

struct header {
	uint8_t		magic[5];		/* = VENOM */
	uint16_t	version;
	uint64_t	iter;
	uint8_t		nonce[DEF_NONCELEN];
	uint8_t		pwcheck[4];
};


/* myname is just the basename of argv[0] made global */
char		*myname;


/* configuration is global for the central encrypt and decrypt
 * functions
 */
int		 conf_iter = DEF_ITERATION;		/* -i <iter> */
int		 conf_verbose = 0;			/* -v */
int		 conf_force = 0;			/* -f */


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



static int
encrypt_file(FILE *in, FILE *out)
{
	uint8_t		 buffer[DEF_BUFSIZE];
	struct header	 header;
	size_t		 n;

	uint8_t		 passwd[DEF_MAXPASSLEN];
	uint8_t		 nonce[DEF_NONCELEN];
	uint8_t		 key[SERPENT_MAX_KEY_SIZE];
	eax_serpent_t	 eax;
	uint8_t		 tag[16];

	
	/* read password from tty (vartime, naturally!) */
	if (read_pass_tty(passwd, sizeof(passwd), "Password", "Confirm") == -1) {
		warnx("can't read password");
		goto errout;
	}

	/* generate random nonce */
	if (secrand(nonce, DEF_NONCELEN) == -1) {
		warnx("can't generate random nonce");
		return -1;
	}
	if (conf_verbose > 1)
		printhex("nonce", nonce, sizeof(nonce));

	if (conf_verbose > 1)
		fprintf(stderr, "iterations: %d\n", conf_iter);


	/* derive encryption key and init encryption (vartime) */
	pbkdf2_hmac_sha512(key, sizeof(key), passwd, sizeof(passwd),
			   nonce, sizeof(nonce), conf_iter);
	
	/* initialize eax-serpent-mode */
	if (eax_serpent_init(&eax, key, sizeof(key)) == -1) {
		warnx("eax-serpent mode initialization failed");
		goto errout;
	}

	
	/* fill header */
	memcpy(header.magic, "VENOM", 5);
	header.version = htobe16(VERSION);
	header.iter = htobe64(conf_iter);
	memcpy(header.nonce, nonce, DEF_NONCELEN);

	/* authenticate magic and nonce for password check */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, sizeof(nonce));
	eax_serpent_header(&eax, header.magic, 5);
	eax_serpent_header(&eax, header.nonce, DEF_NONCELEN);
	eax_serpent_tag(&eax, tag);
	memcpy(header.pwcheck, tag, sizeof(header.pwcheck));
	

	/* write header to output */
	n = fwrite(header.magic, sizeof(header.magic), 1, out);
	if (n != 1) {
		warn("error writing magic");
		goto errout;
	}

	n = fwrite(&header.version, sizeof(header.version), 1, out);
	if (n != 1) {
		warn("error writing file version");
		goto errout;
	}

	n = fwrite(&header.iter, sizeof(header.iter), 1, out);
	if (n != 1) {
		warn("error writing iteration count");
		goto errout;
	}

	n = fwrite(header.nonce, sizeof(header.nonce), 1, out);
	if (n != 1) {
		warn("error writing nonce");
		goto errout;
	}

	n = fwrite(header.pwcheck, sizeof(header.pwcheck), 1, out);
	if (n != 1) {
		warn("error writing password check");
		goto errout;
	}


	/* next nonce, for encrypting our data */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, sizeof(nonce));
	

	/* main loop */
	while ((n = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE, in)) != 0) {
		eax_serpent_encrypt(&eax, buffer, buffer, n);
		
		if (fwrite(buffer, sizeof(uint8_t), n, out) != n) {
			warn("can't write to output file");
			goto errout;
		}
	}
	if (ferror(in)) {
		warn("can't read from input file");
		goto errout;
	}

	/* write final tag */
	eax_serpent_tag(&eax, tag);
	if (conf_verbose > 0)
		printhex("tag", tag, 16);
	
	if (fwrite(tag, sizeof(uint8_t), 16, out) != 16) {
		warn("can't write tag to output");
		goto errout;
	}
	
	/* cleanup */
	burn(passwd, sizeof(passwd));
	burn(key, sizeof(key));
	burn(&eax, sizeof(eax_serpent_t));
	return 0;

errout:
	burn(passwd, sizeof(passwd));
	burn(key, sizeof(key));
	burn(&eax, sizeof(eax_serpent_t));
	return -1;
}



static int
decrypt_file(FILE *in, FILE *out)
{
	uint8_t		 buffer[DEF_BUFSIZE + 16];
	struct header	 header;
	size_t		 n;

	uint8_t		 passwd[DEF_MAXPASSLEN];

	uint8_t		 nonce[DEF_NONCELEN];
	uint8_t		 tag[16];

	uint8_t		 key[SERPENT_MAX_KEY_SIZE];
	eax_serpent_t	 eax;
	

	/* is this really a file from us? */
	n = fread(header.magic, sizeof(header.magic), 1, in);
	if (n != 1) {
		warn("can't read magic from file");
		return -1;
	}
	if (memcmp(header.magic, "VENOM", 5) != 0) {
		warnx("not a venom encrypted file");
		return -1;
	}


	/* check version */
	n = fread(&header.version, sizeof(header.version), 1, in);
	if (n != 1) {
		warn("can't read version from file");
		return -1;
	}
	if (be16toh(header.version) != VERSION) {
		warnx("wrong file version %d (need %d)",
		      be16toh(header.version), VERSION);
		return -1;
	}

	/* read iteration counter for pbkdf2 */
	n = fread(&header.iter, sizeof(header.iter), 1, in);
	if (n != 1) {
		warn("can't read iterations");
		return -1;
	}
	if (conf_verbose > 1)
		fprintf(stderr, "iterations: %ld\n", be64toh(header.iter));


	/* read nonce */
	n = fread(header.nonce, sizeof(header.nonce), 1, in);
	if (n != 1) {
		warn("can't read nonce");
		return -1;
	}
	if (conf_verbose > 1)
		printhex("nonce", header.nonce, sizeof(header.nonce));

	/* and make a working copy */
	memcpy(nonce, header.nonce, sizeof(nonce));

	/* read pwcheck */
	n = fread(header.pwcheck, sizeof(header.pwcheck), 1, in);
	if (n != 1) {
		warn("can't read pwcheck");
		return -1;
	}

	
	/* read password */
	if (read_pass_tty(passwd, sizeof(passwd), "Password", NULL) == -1) {
		warnx("can't read password from terminal");
		goto errout;
	}

	
	/* derive encryption key and init encryption */
	pbkdf2_hmac_sha512(key, sizeof(key), passwd, sizeof(passwd),
			   nonce, sizeof(nonce), be64toh(header.iter));
	
	if (eax_serpent_init(&eax, key, sizeof(key)) == -1) {
		warnx("initializing eax-serpent mode failed");
		goto errout;
	}

	
	/* check for correct password */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, DEF_NONCELEN);
	eax_serpent_header(&eax, header.magic, 5);
	eax_serpent_header(&eax, header.nonce, DEF_NONCELEN);
	eax_serpent_tag(&eax, tag);

	/* check header tag */
	if (memcmp(header.pwcheck, tag, sizeof(header.pwcheck)) != 0) {
		warnx("wrong password");
		goto errout;
	}

	/* next nonce */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, DEF_NONCELEN);


	/* the decryption-mainloop is more complicated because we have
	 * to look out for the final tag. we do that by maintaining a
	 * tag-buffer behind our normal read buffer.
	 */
	
	n = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE+16, in);
	if (n < 16) {
		if (ferror(in))
			warn("can't read from input file");
		else
			warnx("input file is too short");
		
		goto errout;
	}

	/* subtract 16, because this could already be the final tag */
	n -= 16;

	/* main loop: buffer always holding n+16 bytes of data */
	for (;;) {
		eax_serpent_decrypt(&eax, buffer, buffer, n);
		if (fwrite(buffer, sizeof(uint8_t), n, out) != n) {
			warn("can't write to output file");
			goto errout;
		}

		/* copy tag-buffer to beginning */
		memcpy(buffer, buffer+n, 16);
		if (n < DEF_BUFSIZE)
			break;

		/* we are not done: read next chunk of data behind the 16 byte
		 * we still have in our buffer
		 */
		n = fread(buffer+16, sizeof(uint8_t), DEF_BUFSIZE, in);
	}
	if (ferror(in)) {
		warn("can't read from input file");
		goto errout;
	}


	/* calculate and check eax-tag */
	eax_serpent_tag(&eax, tag);
	if (conf_verbose > 0)
		printhex("tag", tag, 16);

	if (memcmp(tag, buffer, 16) != 0) {
		warnx("file is corrupted!");
		if (conf_verbose > 0)
			printhex("file tag", buffer+n, 16);

		goto errout;
	}


	burn(passwd, sizeof(passwd));
	burn(key, sizeof(key));
	burn(&eax, sizeof(eax_serpent_t));
	return 0;

errout:
	burn(passwd, sizeof(passwd));
	burn(key, sizeof(key));
	burn(&eax, sizeof(eax_serpent_t));
	return -1;
}


void
usage()
{
	fprintf(stderr, "Usage: %s [-vfed] [-i <iter>] [<input>] [<output>]\n",
		myname);
}


int
main(int argc, char *argv[])
{
	int		 do_encrypt = -1;	/* -1 for auto detect? */
	char		*inputfn = "-";
	char		*outputfn = "-";

	FILE		*in, *out;
	
	int		 rc;

	myname = x_strdup(basename(argv[0]));

	while ((rc = getopt(argc, argv, "hvfedri:")) != -1) {
		switch (rc) {
		case 'h':
			usage();
			exit(0);
		case 'v':
			conf_verbose++;
			break;

		case 'f':
			conf_force = 1;
			break;
			
		case 'e':
			do_encrypt = 1;
			break;

		case 'd':
			do_encrypt = 0;
			break;

		case 'i':
			conf_iter = atoi(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	
	/* check configuration parameters */
	if (conf_iter < 1024)
		errx(1, "illegal number iteration: %d", conf_iter);

	if (do_encrypt == -1) {
		usage();
		exit(1);
	}

	
	/* handle optional arguments */
	argc -= optind;
	argv += optind;

	if (argc > 0)
		inputfn = argv[0];
	if (argc > 1)
		outputfn = argv[1];

	if (strcmp(inputfn, "-") == 0) 
		in = stdin;
	else {
		in = fopen(inputfn, "r");
		if (in == NULL)
			err(1, "%s: can't open input file", inputfn);
	}

	if (strcmp(outputfn, "-") == 0)
		out = stdout;
	else {
		/* does outputfile already exist? */
		if (!conf_force && exists(outputfn))
			errx(1, "%s: output file already exists, use -f to overwrite", outputfn);
		
		out = fopen(outputfn, "w");
		if (out == NULL)
			err(1, "%s: can't open output file", outputfn);
	}


	/* now do the main work */
	if (do_encrypt)
		rc = encrypt_file(in, out);
	else
		rc = decrypt_file(in, out);


	/* close handles */
	fclose(in);
	fclose(out);

	/* remove output file if encryption/decryption failed */
	if (rc == -1 && strcmp(outputfn, "-") != 0)
		unlink(outputfn);
		
	
	return (rc == -1) ? 1 : 0;
}
