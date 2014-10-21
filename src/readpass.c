#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <err.h>

#include "utils.h"


/*
 * read_line - reads a hole line (i.e until '\n' or EOF is reached)
 * and stores the first max bytes of it into the line buffer. the
 * newline itself is not stored.
 *
 * the line buffer is NOT zero terminated, but instead padded to max
 * bytes with one binary 1 and as much zeros as needed.
 *
 * the length of the original line (without padding but including the
 * cut-off part) is returned, so the caller can check for truncation.
 */
static int
read_line(uint8_t *out, size_t max, FILE *stream)
{
	int count, ch;

	for (count = 0; ; count++) {
		ch = fgetc(stream);
		if (ch == EOF || ch == '\n')
			break;

		if (count < max)
			out[count] = ch;
	}
	if (ferror(stream))
		return -1;

	/* pad, if needed */
	if (count < max) {
		out[count] = 0x80;
		memset(out+count+1, 0, max-count-1);
	}

	return count;
}



/*
 * This function prompts for a password (promptA) and reads it from /dev/tty
 * with fallback to stdin. In case /dev/tty (or stdin) is a terminal and promptB
 * is given, a confirmation is also requested (promptB) and compared to the password.
 * This is repeated until password and confirmation matches.
 *
 * The written password will not be zero terminated, but be padded with
 * a binary one and as much zeros as needed (i.e. one 0x80 and the rest 0x00).
 * The length of the unpadded-password is returned.
 */
int
read_pass_tty(uint8_t *passwd, size_t max, const char *promptA, const char *promptB)
{
	uint8_t		 confirm[max];

	FILE		*input;
	int		 input_fd, input_istty;

	struct termios	 term, term_orig;
	int passlen;
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
			if (input_istty && promptA)
				fprintf(stderr, "%s: ", promptA);

			passlen = read_line(passwd, max, input);
			if (passlen == -1) {
				warn("can't read password");
				goto error2;
			}
			if (passlen > max) {
				/* without a tty this is fatal */
				if (!input_istty) {
					warnx("password to long");
					goto error2;
				}
				fprintf(stderr, "password to long - please try again\n");
			}
		} while (passlen > max);


		/* need a confirmation? */
		if (promptB == NULL || !input_istty)
			break;

		if (input_istty)
			fprintf(stderr, "%s: ", promptB);

		rc = read_line(confirm, max, input);
		if (rc == -1) {
			warn("can't read confirmation");
			goto error2;
		}

		if (memcmp(passwd, confirm, max) == 0)
			break;

		fprintf(stderr, "Passwords do not match, please try again\n");
	}

	/* reset terminal */
	if (input_istty)
		tcsetattr(input_fd, TCSANOW, &term_orig);

	if (input != stdin)
		fclose(input);

	burn(confirm, max);

	return passlen;

error2:
	/* XXX better use TCSAFLUSH? */
	if (input_istty)
		tcsetattr(input_fd, TCSANOW, &term_orig);

error1:
	if (input != stdin)
		fclose(input);

	return -1;
}
