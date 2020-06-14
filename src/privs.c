// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: privs.c
 *
 * Copyright (c) 2002,2003,2004 by Stanislav Ievlev
 * Copyright (C) 2008-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 */
#include "config.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "osec.h"

/** drop process privs */
void drop_privs(char *user, char *group)
{
	cap_t caps;
	struct passwd *pw;
	struct group *gr;

	//cleanup all process groups
	if (setgroups((size_t) 0, NULL) == -1)
		osec_fatal(EXIT_FAILURE, errno, "setgroups");

	//drop group
	if ((gr = getgrnam(group)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "getgrnam");

	if (setgid(gr->gr_gid) == -1)
		osec_fatal(EXIT_FAILURE, errno, "setgid");

	//prepare for droupping user
	if ((pw = getpwnam(user)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "getpwnam");

	if (prctl(PR_SET_KEEPCAPS, 1) == -1)
		osec_fatal(EXIT_FAILURE, errno, "prctl");

	//drop capabilities
	if ((caps = cap_from_text("cap_setuid,cap_dac_read_search=ep")) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "cap_from_text");

	if (cap_set_proc(caps) == -1)
		osec_fatal(EXIT_FAILURE, errno, "cap_set_proc");

	if (cap_free(caps) == -1)
		osec_fatal(EXIT_FAILURE, errno, "cap_free");

	//drop user
	if (setreuid(pw->pw_uid, pw->pw_uid) == -1)
		osec_fatal(EXIT_FAILURE, errno, "setreuid");

	//drop reset capabilities
	if ((caps = cap_from_text("cap_dac_read_search=ep")) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "cap_from_text");

	if (cap_set_proc(caps) == -1)
		osec_fatal(EXIT_FAILURE, errno, "cap_set_proc");

	if (cap_free(caps) == -1)
		osec_fatal(EXIT_FAILURE, errno, "cap_free");
}
