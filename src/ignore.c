/* ignore.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2009-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <string.h>
#include "osec.h"

extern unsigned ignore;

#define E(x) x, sizeof(x) - 1
static const struct ign_opts {
	const char *name;
	const long len;
	const unsigned val;
} ignore_opts[] = {
	{ E("user"),     OSEC_UID },
	{ E("group"),    OSEC_GID },
	{ E("mode"),     OSEC_MOD },
	{ E("inode"),    OSEC_INO },
	{ E("mtime"),    OSEC_MTS },
	{ E("symlink"),  OSEC_LNK },
	{ E("checksum"), OSEC_CSM },
	{ 0, 0, 0 }
};
#undef E

#define MAX(a,b) (((a) > (b)) ? (a) : (b))

static void
set_ignore(char *param, long len) {
	unsigned i = 0;

	if (len <= 0)
		return;

	while (ignore_opts[i].name) {
		if (ignore_opts[i].len == len &&
		    !strncmp(ignore_opts[i].name, param, (size_t) MAX(ignore_opts[i].len, len)))
			ignore |= ignore_opts[i].val;
		i++;
	}
}

void
process_ignore(const char *params) {
	char *ptr = (char *) params;
	size_t len = strlen(params);

	if (!len)
		return;

	while (1) {
		char *delim = strchr(ptr, ',');

		if (delim == NULL) {
			set_ignore(ptr, params + len - ptr);
			break;
		}

		set_ignore(ptr, delim - ptr);
		ptr = delim + 1;
	}
}
