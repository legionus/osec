#ifndef OSEC_H
#define OSEC_H

#define digest_len 20

struct osec_stat {
	mode_t	mode;
	uid_t	uid;
	gid_t	gid;
	char	digest[digest_len]; // SHA1
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
