/* status.c
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
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
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "osec.h"

extern int read_only;
extern int numeric_user_group;

static void
printf_pwname(const char *var, uid_t uid) {
	struct passwd pwbuf, *pw;
	char *buf;
	long pw_bufsize;

	if (!numeric_user_group) {
		pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		buf = (char *) xmalloc((size_t) pw_bufsize);

		getpwuid_r(uid, &pwbuf, &buf[0], (size_t) pw_bufsize, &pw);

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
	struct group grbuf, *gr;
	char *buf;
	long gr_bufsize;

	if (!numeric_user_group) {
		gr_bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
		buf = (char *) xmalloc((size_t) gr_bufsize);

		getgrgid_r(gid, &grbuf, &buf[0], (size_t) gr_bufsize, &gr);

		if (gr != NULL)
			printf(" %s=%s", var, gr->gr_name);
		else
			printf(" %s=#%ld", var, (long) gid);

		xfree(buf);
	}
	else
		printf(" %s=%ld", var, (long) gid);
}

static void
show_state(const char *mode, const char *fname, struct osec_stat *st) {
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

static int
is_bad(struct osec_stat *st) {
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
check_insecure(struct osec_stat *st) {
	if (!is_bad(st))
		return 0;

	printf(" [");

	if (st->mode & S_ISUID)
		printf_pwname((char *) "suid", st->uid);

	if (st->mode & S_ISGID)
		printf_pwname((char *) "sgid", st->gid);

	if (st->mode & S_IWOTH)
		printf(" ww");

	printf(" ]");
	return 1;
}

int
check_new(const char *fname, struct osec_stat *st) {
	if (S_ISREG(st->mode)) {
		printf("%s\tchecksum\tnew\t checksum=", fname);
		show_digest(st->digest);
		printf("\n");
	}
	show_state((char *) "new", fname, st);
	return 1;
}

int
check_difference(const char *fname, struct osec_stat *new_st, struct osec_stat *old_st) {

#define OSEC_ISSET(state,mask) (((state) & mask) == mask)
#define OSEC_FMT 0017
#define OSEC_UID 0010
#define OSEC_GID 0004
#define OSEC_MOD 0002
#define OSEC_INO 0001

	unsigned state = 0;

	if (S_ISREG(new_st->mode) && S_ISREG(old_st->mode)) {
		if (strncmp(old_st->digest, new_st->digest, digest_len) != 0) {
			printf("%s\tchecksum\tchanged\told checksum=", fname);
			show_digest(old_st->digest);

			printf("\tnew checksum=");
			show_digest(new_st->digest);

			printf("\n");
		}
	}

	if (old_st->uid  != new_st->uid)  state ^= OSEC_UID;
	if (old_st->gid  != new_st->gid)  state ^= OSEC_GID;
	if (old_st->mode != new_st->mode) state ^= OSEC_MOD;
	if (old_st->ino  != new_st->ino)  state ^= OSEC_INO;

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
check_bad_files(const char *fname, struct osec_stat *st) {
	if (!is_bad(st))
		return 0;
	show_state((char *) "info", fname, st);
	return 1;
}

int
check_removed(const char *fname, struct osec_stat *st) {
	if (S_ISREG(st->mode)) {
		printf("%s\tchecksum\tremoved\t checksum=", fname);
		show_digest(st->digest);
		printf("\n");
	}
	show_state((char *) "removed", fname, st);
	return 1;
}
