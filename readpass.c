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
 * read_pass - read a password from file or user.
 *
 * If input stream fp is a terminal (like /dev/tty) and promptA and promptB are
 * are not NULL they are used to prompt the user for a password and a password 
 * confirmation. This is repeated until both entries are equal.
 *
 * If fp is not a terminal, the password is read just one time (even if
 * promptB is given).
 *
 * Instead of zero-terminating the password it's length will be returned.
 * But the password will be padded to max bytes, by attaching one binary zero
 * and as much zeros as needed. This could be used to work with constant-length
 * passwords.
 */
int
read_pass(FILE *fp, uint8_t *passwd, size_t max, const char *promptA, const char *promptB)
{
	uint8_t		 confirm[max];

	int		 fp_fd, fp_istty;

	struct termios	 term, term_orig;
	int		 passlen;
	int		 rc;


	fp_fd = fileno(fp);
	fp_istty = isatty(fp_fd);

	if (fp_istty) {
		if (tcgetattr(fp_fd, &term) == -1) {
			warn("can't read terminal attributes");
			return -1;
		}

		memcpy(&term_orig, &term, sizeof(struct termios));
		term.c_lflag &= ~ECHO;
		term.c_lflag |= ECHONL;

		if (tcsetattr(fp_fd, TCSANOW, &term) == -1) {
			warn("can't write terminal attributes");
			return -1;
		}
	}

	for (;;) {
		do {
			if (fp_istty && promptA)
				fprintf(stderr, "%s", promptA);

			passlen = read_line(passwd, max, fp);
			if (passlen == -1) {
				warn("can't read password");
				goto errout;
			}
			if (passlen > max) {
				/* without a tty this is fatal */
				if (!fp_istty) {
					warnx("password to long");
					goto errout;
				}
				fprintf(stderr, "password to long - please try again\n");
			}
		} while (passlen > max);


		/* need a confirmation? */
		if (promptB == NULL || !fp_istty)
			break;

		if (fp_istty)
			fprintf(stderr, "%s", promptB);

		rc = read_line(confirm, max, fp);
		if (rc == -1) {
			warn("can't read confirmation");
			goto errout;
		}

		if (memcmp(passwd, confirm, max) == 0)
			break;

		fprintf(stderr, "Passwords do not match, please try again\n");
	}

	/* reset terminal */
	if (fp_istty)
		tcsetattr(fp_fd, TCSANOW, &term_orig);

	return passlen;

errout:
	/* XXX better use TCSAFLUSH? */
	if (fp_istty)
		tcsetattr(fp_fd, TCSANOW, &term_orig);

	return -1;
}
