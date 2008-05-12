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

static char *
get_pwname(char *var, uid_t uid) {
	int rc = 0;
	struct passwd pwbuf, *pw;
	char *buf, *outl;
	long pw_bufsize;

	if (!numeric_user_group) {
		pw_bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		buf = (char *) x_malloc((size_t) pw_bufsize);

		getpwuid_r(uid, &pwbuf, &buf[0], (size_t) pw_bufsize, &pw);

		if (pw != NULL)
			rc = asprintf(&outl, " %s=%s", var, pw->pw_name);
		else
			rc = asprintf(&outl, " %s=#%ld", var, (long) uid);

		x_free(buf);
	}
	else
		rc = asprintf(&outl, " %s=%ld", var, (long) uid);

	if (rc == -1)
		osec_fatal(EXIT_FAILURE, errno, "asprintf");

	return outl;
}

static char *
get_grname(char *var, gid_t gid) {
	int rc = 0;
	struct group grbuf, *gr;
	char *buf, *outl;
	long gr_bufsize;

	if (!numeric_user_group) {
		gr_bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
		buf = (char *) x_malloc((size_t) gr_bufsize);

		getgrgid_r(gid, &grbuf, &buf[0], (size_t) gr_bufsize, &gr);

		if (gr != NULL)
			rc = asprintf(&outl, " %s=%s", var, gr->gr_name);
		else
			rc = asprintf(&outl, " %s=#%ld", var, (long) gid);

		x_free(buf);
	}
	else
		rc = asprintf(&outl, " %s=%ld", var, (long) gid);

	if (rc == -1)
		osec_fatal(EXIT_FAILURE, errno, "asprintf");

	return outl;
}

static void
show_state(char *mode, char *fname, struct osec_stat *st) {
	char *pwname, *grname;

	printf("%s\tstat\t%s\t", fname, mode);

	pwname = get_pwname((char *) "uid", st->uid);
	grname = get_grname((char *) "gid", st->gid);

	printf("%s%s mode=%lo", pwname, grname, (unsigned long) st->mode);

	x_free(pwname);
	x_free(grname);

	check_insecure(st);
	printf("\n");
}

static void
show_digest(char *dst) {
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
	char *buf;

	if (!is_bad(st))
		return 0;

	printf(" [");

	if (st->mode & S_ISUID) {
		buf = get_pwname((char *) "suid", st->uid);
		printf("%s", buf);
		x_free(buf);
	}

	if (st->mode & S_ISGID) {
		buf = get_pwname((char *) "sgid", st->gid);
		printf("%s", buf);
		x_free(buf);
	}

	if (st->mode & S_IWOTH)
		printf(" ww");

	printf(" ]");
	return 1;
}

int
check_new(char *fname, struct osec_stat *st) {
	if (S_ISREG(st->mode)) {
		printf("%s\tmd5\tnew\t md5sum=", fname);
		show_digest(st->digest);
		printf("\n");
	}
	show_state((char *) "new", fname, st);
	return 1;
}

int
check_difference(char *fname, struct osec_stat *new_st, struct osec_stat *old_st) {
	int i, differ = 0;
	char *old[] = { NULL, NULL, NULL },
	     *new[] = { NULL, NULL, NULL };

	if (S_ISREG(new_st->mode) || S_ISREG(old_st->mode)) {
		if (strncmp(old_st->digest, new_st->digest, digest_len) != 0) {
			printf("%s\tmd5\tchanged\told md5sum=", fname);
			show_digest(old_st->digest);

			printf("\tnew md5sum=");
			show_digest(new_st->digest);

			printf("\n");
		}
	}

	if (old_st->uid != new_st->uid) {
		old[0] = get_pwname((char *) "uid", old_st->uid);
		new[0] = get_pwname((char *) "uid", new_st->uid);
		differ = 1;
	}

	if (old_st->gid != new_st->gid) {
		old[1] = get_grname((char *) "gid", old_st->gid);
		new[1] = get_grname((char *) "gid", new_st->gid);
		differ = 1;
	}

	if (old_st->mode != new_st->mode) {
		if (asprintf(&(old[2]), " mode=%lo", (unsigned long) old_st->mode) == -1)
			osec_fatal(EXIT_FAILURE, errno, "asprintf");

		if (asprintf(&(new[2]), " mode=%lo", (unsigned long) new_st->mode) == -1)
			osec_fatal(EXIT_FAILURE, errno, "asprintf");
		differ = 1;
	}

	if (differ) {
		printf("%s\tstat\tchanged\told", fname);
		for (i = 0; i < 3; i++) {
			if (old[i] == NULL)
				continue;
			printf("%s", old[i]);
			x_free(old[i]);
		}
		check_insecure(old_st);

		printf("\tnew");
		for (i = 0; i < 3; i++) {
			if (new[i] == NULL)
				continue;
			printf("%s", new[i]);
			x_free(new[i]);
		}
		check_insecure(new_st);

		printf("\n");
	}

	return differ;
}

int
check_bad_files(char *fname, struct osec_stat *st) {
	if (!is_bad(st))
		return 0;
	show_state((char *) "info", fname, st);
	return 1;
}

int
check_removed(char *fname, struct osec_stat *st) {
	if (S_ISREG(st->mode)) {
		printf("%s\tmd5\tremoved\t md5sum=", fname);
		show_digest(st->digest);
		printf("\n");
	}
	show_state((char *) "removed", fname, st);
	return 1;
}
