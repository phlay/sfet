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

/*
 * TODO:
 * - make longer passwords possible by tweaking our PRF for pbkdf2
 * - test on other platforms
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
#include "pbkdf2-omac-serpent.h"


#define VERSION		5


/*
 * header definition for a venom file
 */

struct header {
	uint8_t		magic[5];		/* = VENOM */
	uint16_t	version;
	uint32_t	iter;
	uint8_t		nonce[DEF_NONCELEN];
	uint8_t		pwcheck[4];
} __attribute__((packed));


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
printhex(const char *label, const uint8_t *vec, size_t len)
{
	int i;
	
        fprintf(stderr, "%s: ", label);
        if (len)
                for (i = 0; i < len; i++)
                        fprintf(stderr, "%02x", vec[i]);
        else
                fputc('-', stderr);

        fputc('\n', stderr);
}




static int
encrypt_file(FILE *in, FILE *out)
{
	uint8_t		 buffer[DEF_BUFSIZE];
	struct header	*header;

	char		 passwd[DEF_MAXPASSLEN+2];
	uint8_t		 nonce[DEF_NONCELEN];
	uint8_t		 key[SERPENT_MAX_KEY_SIZE];
	eax_serpent_t	 eax;
	uint8_t		 tag[16];

	size_t		 len;
	
	
	/* generate random nonce; since we actually need three nonces,
	 * we use the first byte as counter.
	 */
	if (getrandom(nonce, DEF_NONCELEN) == -1) {
		warnx("can't generate random nonce");
		return -1;
	}
	if (conf_verbose > 1)
		printhex("nonce", nonce, sizeof(nonce));

	if (conf_verbose > 1)
		fprintf(stderr, "iterations: %d\n", conf_iter);

	/* read password from tty */
	if (read_pass_tty(passwd, sizeof(passwd), "Password", "Confirm") == -1) {
		warnx("can't read password");
		goto errout;
	}

	/* derive encryption key and init encryption */
	if (pbkdf2_omac_serpent(key, sizeof(key), passwd,
				nonce, sizeof(nonce), conf_iter) == -1) {
		warnx("key expansion failed");
		goto errout;
        }
	
	/* initialize eax-serpent-mode */
	if (eax_serpent_init(&eax, key, sizeof(key)) == -1) {
		warnx("eax-serpent mode initialization failed");
		goto errout;
	}

	
	/* fill header */
	header = (struct header *)buffer;
	memcpy(header->magic, "VENOM", 5);
	header->version = htobe16(VERSION);
	header->iter = htobe32(conf_iter);
	memcpy(header->nonce, nonce, DEF_NONCELEN);


	/* authenticate magic and nonce for password check */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, sizeof(nonce));
	eax_serpent_header(&eax, header->magic, 5);
	eax_serpent_header(&eax, header->nonce, DEF_NONCELEN);
	eax_serpent_tag(&eax, tag);

	memcpy(header->pwcheck, tag, sizeof(header->pwcheck)); 
	

	/* write header to output */
	if (fwrite(buffer, sizeof(struct header), 1, out) != 1) {
		warn("error writing header");
		goto errout;
	}
	

	/* next nonce, for encrypting our data */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, sizeof(nonce));
	

	/* main loop */
	while ((len = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE, in)) != 0) {
		eax_serpent_encrypt(&eax, buffer, buffer, len);
		
		if (fwrite(buffer, sizeof(uint8_t), len, out) != len) {
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
	uint8_t			 buffer[DEF_BUFSIZE + 16];
	const struct header	*header = (const struct header *)buffer;

	char			 passwd[DEF_MAXPASSLEN+2];

	uint8_t			 nonce[DEF_NONCELEN];
	uint8_t			 tag[16];

	uint8_t			 key[SERPENT_MAX_KEY_SIZE];
	eax_serpent_t		 eax;

	size_t			 len;
	
	/* read header from file */
	if (fread(buffer, sizeof(struct header), 1, in) != 1) {
		warn("can't read from input file");
		return -1;
	}

	/* is this really a file from us? */
	if (memcmp(header->magic, "VENOM", 5) != 0) {
		warnx("not a venom encrypted file");
		return -1;
	}

	/* check version */
	if (be16toh(header->version) != VERSION) {
		warnx("wrong file version %d (need %d)",
		      be16toh(header->version), VERSION);
		return -1;
	}
		
	/* copy nonce, since we are changing it */
	memcpy(nonce, header->nonce, DEF_NONCELEN);
	
	if (conf_verbose > 1)
		printhex("nonce", nonce, sizeof(nonce));

	if (conf_verbose > 1)
		fprintf(stderr, "iterations: %d\n", be32toh(header->iter));

	
	/* read password */
	if (read_pass_tty(passwd, sizeof(passwd), "Password", NULL) == -1) {
		warnx("can't read password from terminal");
		goto errout;
	}

	
	/* derive encryption key and init encryption */
	if (pbkdf2_omac_serpent(key, sizeof(key), passwd, nonce,
				sizeof(nonce), be32toh(header->iter)) == -1) {
		warnx("pbkdf2 failed");
		goto errout;
	}
	
	if (eax_serpent_init(&eax, key, sizeof(key)) == -1) {
		warnx("initializing eax-serpent mode failed");
		goto errout;
	}

	
	/* check for correct password */
	nonce[0]++;
	eax_serpent_nonce(&eax, nonce, DEF_NONCELEN);
	eax_serpent_header(&eax, header->magic, 5);
	eax_serpent_header(&eax, header->nonce, DEF_NONCELEN);
	eax_serpent_tag(&eax, tag);

	/* check header tag */
	if (memcmp(header->pwcheck, tag, sizeof(header->pwcheck)) != 0) {
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
	
	len = fread(buffer, sizeof(uint8_t), DEF_BUFSIZE+16, in);
	if (len < 16) {
		if (ferror(in))
			warn("can't read from input file");
		else
			warnx("input file is too short");
		
		goto errout;
	}

	/* subtract 16, because this could already be the final tag */
	len -= 16;

	/* main loop: buffer always holds len+16 bytes of data */
	for (;;) {
		eax_serpent_decrypt(&eax, buffer, buffer, len);
		if (fwrite(buffer, sizeof(uint8_t), len, out) != len) {
			warn("can't write to output file");
			goto errout;
		}

		/* copy tag-buffer to beginning */
		memcpy(buffer, buffer+len, 16);
		if (len < DEF_BUFSIZE)
			break;

		/* we are not done: read next chunk of data behind the 16 byte
		 * we still have in our buffer
		 */
		len = fread(buffer+16, sizeof(uint8_t), DEF_BUFSIZE, in);
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
			printhex("read tag", buffer+len, 16);

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
