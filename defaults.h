#ifndef DEFAULTS_H
#define DEFAULTS_H

#include <sys/stat.h>

#include "serpent.h"

#define DEF_BUFSIZE	1048576

#define DEF_ITERATION	256000
#define DEF_NONCELEN	16

#define DEF_PASSWD_SRC	"/dev/tty"

#define DEF_MODE_ENC	S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH
#define DEF_MODE_DEC	S_IRUSR|S_IWUSR

#endif
