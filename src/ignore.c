/* ignore.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */

#include <alloca.h>
#include <string.h>
#include "osec.h"

extern unsigned ignore;

static void
set_ignore(char *param) {
	if      (!strcmp("user",  param)) ignore |= OSEC_UID;
	else if (!strcmp("group", param)) ignore |= OSEC_GID;
	else if (!strcmp("mode",  param)) ignore |= OSEC_MOD;
	else if (!strcmp("inode", param)) ignore |= OSEC_INO;
}

void
process_ignore(char *param) {
	char *e, *str;
	size_t len = strlen(param);

	if (!len)
		return;

	str = alloca(sizeof(char) * (len + 1));
	strcpy(str, param);

	while ((e = strchr(str, ',')) != NULL) {
		*e = '\0';
		set_ignore(str);
		str = e+1;
	}
	if (str != '\0')
		set_ignore(str);
}
