/* status.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "osec.h"

extern int numeric_user_group;
extern unsigned ignore;

static void
printf_pwname(const char *var, uid_t uid) {
	struct passwd pwbuf, *pw;
	char *buf;
	long pw_bufsize;

	if (!numeric_user_group) {
		pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		buf = (char *) xmalloc((size_t) pw_bufsize);

		getpwuid_r(uid, &pwbuf, buf, (size_t) pw_bufsize, &pw);

		if (pw != NULL)
			printf(" %s=%s", var, pw->pw_name);
		else
			printf(" %s=#%ld", var, (long) uid);

		xfree(buf);
	}
	else
		printf(" %s=%ld", var, (long) uid);
}

static void
printf_grname(const char *var, gid_t gid) {
	struct group grbuf, *gr = NULL;
	char *buf;
	long gr_bufsize;

	if (!numeric_user_group) {
		gr_bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
		buf = (char *) xmalloc((size_t) gr_bufsize);

		getgrgid_r(gid, &grbuf, buf, (size_t) gr_bufsize, &gr);

		if (gr != NULL)
			printf(" %s=%s", var, gr->gr_name);
		else
			printf(" %s=#%ld", var, (long) gid);

		xfree(buf);
	}
	else
		printf(" %s=%ld", var, (long) gid);
}

static int
is_bad(osec_stat_t *st) {
	if (!(st->mode & (S_ISUID|S_ISGID|S_IWOTH)))
		return 0;

	//skip suid or sgid directory
	if (S_ISDIR(st->mode) && !(st->mode & S_IWOTH))
		return 0;

	//skip symlinks
	if (S_ISLNK(st->mode))
		return 0;

	return 1;
}

int
check_insecure(osec_stat_t *st) {
	if (!is_bad(st))
		return 0;

	printf(" [");

	if (st->mode & S_ISUID)
		printf_pwname((char *) "suid", st->uid);

	if (st->mode & S_ISGID)
		printf_grname((char *) "sgid", st->gid);

	if (st->mode & S_IWOTH)
		printf(" ww");

	printf(" ]");
	return 1;
}

static void
show_state(const char *mode, const char *fname, osec_stat_t *st) {
	printf("%s\tstat\t%s\t", fname, mode);

	printf_pwname((char *) "uid", st->uid);
	printf_grname((char *) "gid", st->gid);
	printf(" mode=%lo inode=%ld", (unsigned long) st->mode, (long) st->ino);

	check_insecure(st);
	printf("\n");
}

static void
show_digest(const char *dst) {
	int i = 0;
	while (i < digest_len)
		printf("%02x", (unsigned char) dst[i++]);
}

int
check_new(const char *fname, void *data, size_t dlen) {
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, dlen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

	if (S_ISREG(st->mode)) {
		char *csum;

		if ((csum = osec_field(OVALUE_CSUM, data, dlen)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

		printf("%s\tchecksum\tnew\t checksum=", fname);
		show_digest(csum);
		printf("\n");
	}
	show_state((char *) "new", fname, st);
	return 1;
}

static void
check_checksum(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	char *old, *new;

	if ((old = osec_field(OVALUE_CSUM, odata, olen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'checksum' from database value\n",
			fname);

	if ((new = osec_field(OVALUE_CSUM, ndata, nlen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'checksum' from database value\n",
			fname);

	if (strncmp(old, new, (size_t) digest_len) != 0) {
		printf("%s\tchecksum\tchanged\told checksum=", fname);
		show_digest(old);

		printf("\tnew checksum=");
		show_digest(new);

		printf("\n");
	}
}

static void
check_symlink(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	char *old, *new;

	if ((old = (char *) osec_field(OVALUE_LINK, odata, olen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'symlink' from database value\n",
			fname);

	if ((new = (char *) osec_field(OVALUE_LINK, ndata, nlen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'symlink' from database value\n",
			fname);

	if (strcmp(old, new) != 0)
		printf("%s\tsymlink\tchanged\told target=%s\tnew target=%s\n",
			fname, old, new);
}

int
check_difference(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	osec_stat_t *new_st, *old_st;
	unsigned state = 0;

	if ((old_st = osec_field(OVALUE_STAT, odata, olen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'stat' from database value\n",
			fname);

	if ((new_st = osec_field(OVALUE_STAT, ndata, nlen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'stat' from database value\n",
			fname);

	if (S_ISREG(new_st->mode) && S_ISREG(old_st->mode))
		check_checksum(fname, ndata, nlen, odata, olen);

	else if (S_ISLNK(new_st->mode) && S_ISLNK(old_st->mode))
		check_symlink(fname, ndata, nlen, odata, olen);

	if (!OSEC_ISSET(ignore, OSEC_UID) && old_st->uid  != new_st->uid)  state ^= OSEC_UID;
	if (!OSEC_ISSET(ignore, OSEC_GID) && old_st->gid  != new_st->gid)  state ^= OSEC_GID;
	if (!OSEC_ISSET(ignore, OSEC_MOD) && old_st->mode != new_st->mode) state ^= OSEC_MOD;
	if (!OSEC_ISSET(ignore, OSEC_INO) && old_st->ino  != new_st->ino)  state ^= OSEC_INO;

	if (!(state & OSEC_FMT))
		return 0;

	printf("%s\tstat\tchanged\told", fname);

	/* Old state */
	if (OSEC_ISSET(state, OSEC_UID))
		printf_pwname((char *) "uid", old_st->uid);

	if (OSEC_ISSET(state, OSEC_GID))
		printf_grname((char *) "gid", old_st->gid);

	if (OSEC_ISSET(state, OSEC_MOD))
		printf(" mode=%lo", (unsigned long) old_st->mode);

	if (OSEC_ISSET(state, OSEC_INO))
		printf(" inode=%ld", (long) old_st->ino);

	check_insecure(old_st);

	/* New state */
	printf("\tnew");

	if (OSEC_ISSET(state, OSEC_UID))
		printf_pwname((char *) "uid", new_st->uid);

	if (OSEC_ISSET(state, OSEC_GID))
		printf_grname((char *) "gid", new_st->gid);

	if (OSEC_ISSET(state, OSEC_MOD))
		printf(" mode=%lo", (unsigned long) new_st->mode);

	if (OSEC_ISSET(state, OSEC_INO))
		printf(" inode=%ld", (long) new_st->ino);

	check_insecure(new_st);
	printf("\n");
	return 1;
}


int
check_bad_files(const char *fname, void *data, size_t len) {
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, len)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field: Unable to get 'stat' from database value\n",
			fname);

	if (!is_bad(st))
		return 0;

	show_state((char *) "info", fname, st);
	return 1;
}

int
check_removed(const char *fname, void *data, size_t len) {
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, len)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field: Unable to get 'stat' from database value\n",
			fname);

	if (S_ISREG(st->mode)) {
		char *csum;

		if ((csum = osec_field(OVALUE_CSUM, data, len)) == NULL)
			osec_fatal(EXIT_FAILURE, 0,
				"%s: osec_field: Unable to get 'checksum' from database value\n",
				fname);

		printf("%s\tchecksum\tremoved\t checksum=", fname);
		show_digest(csum);
		printf("\n");
	}
	show_state((char *) "removed", fname, st);
	return 1;
}
