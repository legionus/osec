/* osec.h
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#ifndef OSEC_H
#define OSEC_H

#define digest_len 20

struct osec_stat {
	ino_t	ino;			/* inode number */
	mode_t	mode;			/* file's permission bits */
	uid_t	uid;			/* user ID of owner */
	gid_t	gid;			/* group ID of owner */
	char	digest[digest_len];	/* file's checksum */
};

/* common.c */
void osec_fatal(const int exitnum, const int errnum, const char *fmt, ...);
int osec_error(const char *fmt, ...);

/* memory.c */
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void xfree(void *ptr);

/* privs.c */
void drop_privs(char *user, char *group);

/* status.c */
/* Return 1 if check is true. Otherwise, 0 is returned. */
int check_insecure(struct osec_stat *st);
int check_new(const char *fname, struct osec_stat *st);
int check_difference(const char *fname, struct osec_stat *new, struct osec_stat *old);
int check_bad_files(const char *fname, struct osec_stat *st);
int check_removed(const char *fname, struct osec_stat *st);

/* digest.c */
void digest(const char *fname, struct osec_stat *st);

#endif /* OSEC_H */
