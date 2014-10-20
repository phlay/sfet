/*
 * utils - various helper functions for venom
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. 
 */
 
#include <sys/types.h>
#include <sys/stat.h>

#include <termios.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include "defaults.h"
#include "utils.h"

void *
x_malloc(size_t size)
{
        void *rval;

        rval = malloc(size);
        if (rval == NULL)
                err(1, "can't allocate memory");
        
        return rval;
}

char *
x_strdup(const char *s)
{
        char *rval;

        rval = strdup(s);
        if (rval == NULL)
                err(1, "can't duplicate string");

        return rval;
}

int
exists(const char *path)
{
        struct stat sb;
	return (stat(path, &sb) == -1) ? 0 : 1;
}


void
burn(void *buf, size_t len)
{
	memset(buf, 0, len);
}


int
getrandom(uint8_t *buf, size_t len)
{
        FILE *dev;

        dev = fopen(DEF_RANDDEV, "r");
        if (dev == NULL)
                return -1;

        if (fread(buf, sizeof(uint8_t), len, dev) != len) {
                fclose(dev);
                return -1;
        }

        fclose(dev);
        return 0;
}

/*
 * read_line - reads a hole line (i.e until '\n' or EOF is reached) and stores
 * at most max-1 bytes of it into the line buffer. If EOF is reached an
 * error (-1) is returned.
 */
int
read_line(char *line, size_t max, FILE *stream)
{
	int c;
	char *ptr = line;
	char *endp = line + max;

	while ((c = fgetc(stream)) != EOF) {
		if (c == '\n') {
			if (ptr < endp)
				*ptr = '\0';
			return ptr-line;
		}

		if (ptr < endp)
			*ptr++ = c;
	}
	
	/* found EOF */
	return -1;
}

/*
 * This function prompts for a password (promptA) and reads it from /dev/tty
 * with fallback to stdin. In case /dev/tty (or stdin) is a terminal and promptB
 * is given, a confirmation is also requested (promptB) and compared to the password.
 * This is repeated until password and confirmation matches.
 */
int
read_pass_tty(char *passwd, size_t max, const char *promptA, const char *promptB)
{
	char		 confirm[max];

	FILE		*input;
	int		 input_fd, input_istty;
	
	struct termios	 term, term_orig;
	int rc;

	input = fopen("/dev/tty", "r");
	if (input == NULL)
		input = stdin;

	input_fd = fileno(input);
	input_istty = isatty(input_fd);

	if (input_istty) {
		if (tcgetattr(input_fd, &term) == -1) {
			warn("can't read terminal attributes");
			goto error1;
		}

		memcpy(&term_orig, &term, sizeof(struct termios));
		term.c_lflag &= ~ECHO;
		term.c_lflag |= ECHONL;

		if (tcsetattr(input_fd, TCSANOW, &term) == -1) {
			warn("can't write terminal attributes");
			goto error1;
		}
	}

	for (;;) {
		do {
			if (input_istty) fprintf(stderr, "%s: ", promptA);
			rc = read_line(passwd, max, input);
			if (rc == -1) {
				warn("can't read password");
				goto error2;
			}
			if (rc == max)
				warnx("password to long - try again");
		} while (rc == max);
		

		/* need a confirmation? */
		if (promptB == NULL || !input_istty)
			break;

		if (input_istty) fprintf(stderr, "%s: ", promptB);
		rc = read_line(confirm, max, input);
		if (rc == -1) {
			warn("can't read confirmation");
			goto error2;
		}

		if (strcmp(passwd, confirm) == 0)
			break;
		
		warnx("Passwords do not match, please try again");
	}

	/* reset terminal */
	if (input_istty)
		tcsetattr(input_fd, TCSANOW, &term_orig);

	if (input != stdin)
		fclose(input);

	burn(confirm, max);

	return 0;

error2:
	/* XXX better use TCSAFLUSH? */
	if (input_istty)
		tcsetattr(input_fd, TCSANOW, &term_orig);

error1:
	if (input != stdin)
		fclose(input);
	
	return -1;
}
