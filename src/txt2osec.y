// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: txt2osec.y
 *
 *  Copyright (C) 2010-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 *  Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */
%{
#define YYSTYPE long long

#include "config.h"

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"

extern FILE *yyin;

char str[PATH_MAX];

char *pathname = NULL;
int line_nr    = 1;

#define F_ISSET(state,mask) (((state) & (mask)) == (mask))
enum {
	FLAG_FILE  = (01 << 0),
	FLAG_CSUM  = (01 << 1),
	FLAG_LINK  = (01 << 2),
	FLAG_MODE  = (01 << 3),
	FLAG_MTIME = (01 << 4),
	FLAG_DEV   = (01 << 5),
	FLAG_INO   = (01 << 6),
	FLAG_UID   = (01 << 7),
	FLAG_GID   = (01 << 8),
	FLAG_XATTR = (01 << 9),
};

char *fname = NULL;
char *slink = NULL;
char **chsum = NULL;
size_t chsum_count = 0;
char *xattr = NULL;
char *hashnames = NULL;
char *basepath = NULL;

osec_stat_t ost;

struct record rec;

struct cdb_make cdbm;
long flags = 0;

struct database_metadata current_db = { 0 };

void print_help(int ret)
	__attribute__((noreturn));
void print_version(void)
	__attribute__((noreturn));
int yyerror(const char *s);
int yylex (void);

%}

/* BISON Declarations */
%token FILENAME DEVICE INODE UID GID MTIME CHECKSUM SYMLINK MODE
%token EQUALS DOT EOL ERROR
%token NUMBER OCTAL STRLITERAL
%token HASHNAMES BASEPATH
%token XATTR

/* Grammar follows */
%%
input		: /* empty string */
		| input line
 		;
line		: endline
		| fileline range endline
		| hashline eol
		| basepathline eol
		;
range		: range range0
		| range0
		;
range0		: devline
		| inoline
		| uidline
		| gidline
		| mtimeline1
		| mtimeline2
		| csumline
		| linkline
		| modeline
		| xattrline
		;
hashline	: HASHNAMES EQUALS STRLITERAL
		{
			if (current_db.basepath != NULL)
				osec_fatal(EXIT_FAILURE, 0, "%s:%d: duplicate field: hashnames",
					pathname, line_nr);
			hashnames = strdup(str);
		}
		;
basepathline	: BASEPATH EQUALS STRLITERAL
		{
			if (current_db.basepath != NULL)
				osec_fatal(EXIT_FAILURE, 0, "%s:%d: duplicate field: basepath",
					pathname, line_nr);
			current_db.basepath = strdup(str);
		}
		;
fileline	: FILENAME EQUALS STRLITERAL
		{
			fname = strdup(str);
			if (!fname) {
				osec_error("strdup: %m");
				exit(EXIT_FAILURE);
			}
			flags |= FLAG_FILE;
		}
		;
csumline	: CHECKSUM EQUALS STRLITERAL
		{
		  char *delim, *ptr;
		  size_t n = strlen(str);

		  delim = strchr(str, ':');
		  if (delim != NULL) {
			n = strlen(delim + 1);
		  }

		  if ((n % 2) != 0)
			osec_fatal(1, 0, "%s:%d: Checksum value invalid size: %s",
			           pathname, line_nr, str);

		  ++chsum_count;
		  chsum = realloc(chsum, sizeof(char*) * chsum_count);
		  if (!chsum) {
			osec_error("realloc: %m");
			exit(EXIT_FAILURE);
		  }

		  ptr = strdup(str);
		  if (!ptr) {
			osec_error("strdup: %m");
			free(chsum);
			exit(EXIT_FAILURE);
		  }
		  chsum[chsum_count - 1] = ptr;

		  flags |= FLAG_CSUM;
		}
		;
xattrline	: XATTR EQUALS STRLITERAL
		{
		  size_t n = strlen(str);
		  if (n % 2 != 0)
			osec_fatal(1, 0, "%s:%d: Xattr value has invalid size: %s",
			           pathname, line_nr, str);
		  xattr = strdup(str);
		  if (!xattr) {
			osec_error("strdup: %m");
			exit(EXIT_FAILURE);
		  }
		  flags |= FLAG_XATTR;
		}
		;
linkline	: SYMLINK EQUALS STRLITERAL
		{
			if (strlen(str) > 0) {
				slink = strdup(str);
				if (!slink) {
					osec_error("strdup: %m");
					exit(EXIT_FAILURE);
				}
				flags |= FLAG_LINK;
			}
		}
		;
devline		: DEVICE EQUALS NUMBER
		{ ost.dev = (dev_t) $3;
		  flags |= FLAG_DEV; }
		;
inoline		: INODE EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: Inode value too long: %lld",
			           pathname, line_nr, $3);
		  ost.ino = (ino_t) $3;
		  flags |= FLAG_INO; }
		;
uidline		: UID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: UID value too long: %lld",
			           pathname, line_nr, $3);
		  ost.uid = (uid_t) $3;
		  flags |= FLAG_UID; }
		;
gidline		: GID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: GID value too long: %lld",
			           pathname, line_nr, $3);
		  ost.gid = (gid_t) $3;
		  flags |= FLAG_GID; }
		;
mtimeline1	: MTIME EQUALS NUMBER DOT NUMBER
		{ ost.mtime = (int64_t) $3;
		  ost.mtime_nsec = (int64_t) $5;
		  flags |= FLAG_MTIME; }
		;
mtimeline2	: MTIME EQUALS NUMBER
		{ ost.mtime = (int64_t) $3;
		  ost.mtime_nsec = 0;
		  flags |= FLAG_MTIME; }
		;
modeline	: MODE EQUALS OCTAL
		{ ost.mode = (mode_t) $3;
		  flags |= FLAG_MODE; }
		;
eol		: EOL
		{
		}
		;
endline		: EOL
		{
			rec.offset = 0;

			if (!F_ISSET(flags, FLAG_FILE | FLAG_DEV | FLAG_INO | FLAG_UID | FLAG_GID | FLAG_MODE))
				osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format",
				           pathname, line_nr);

			if (!append_value(OVALUE_STAT, &ost, sizeof(ost), &rec))
				exit(EXIT_FAILURE);

			if (F_ISSET(flags, FLAG_XATTR)) {
				char *s = xattr;
				unsigned int h;
				size_t i;
				size_t xattr_len;
				unsigned char *xattr_str = NULL;

				xattr_len = strlen(xattr) / 2;
				xattr_str = malloc(xattr_len);

				if (!xattr_str) {
					osec_error("malloc: %m");
					exit(EXIT_FAILURE);
				}

				for (i = 0; i < xattr_len; i++) {
					sscanf(s, "%02x", &h);
					xattr_str[i] = (unsigned char) h;
					s += 2;
				}
				if (!append_value(OVALUE_XATTR, xattr_str, xattr_len, &rec))
					exit(EXIT_FAILURE);
				free(xattr);
				free(xattr_str);
			}
			else
			{
				/* if not xattr is found, it's probably data from database before version 3, just add empty xattr value for compatibility */
				const char empty = '\0';
				if (!append_value(OVALUE_XATTR, &empty, sizeof(empty), &rec))
					exit(EXIT_FAILURE);
			}

			if (F_ISSET(flags, FLAG_CSUM)) {
				unsigned int h, i;
				size_t z;

				char *buffer = NULL;
				size_t buffer_size = 0;

				struct record local_rec = { 0 };

				if (!S_ISREG(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: checksum field for not regular file",
					           pathname, line_nr);

				for (z = 0; z < chsum_count; ++z) {
					size_t namelen;
					const char *name;
					size_t digestlen;
					const char *digest;
					char *delim;

					delim = strchr(chsum[z], ':');
					if (delim != NULL) {
						namelen = delim - chsum[z];
						name = chsum[z];
						digestlen = strlen(delim + 1) / 2;
						digest = delim + 1;
					} else {
						namelen = sizeof("sha1") - 1;
						name = "sha1";
						digestlen = strlen(chsum[z]) / 2;
						digest = chsum[z];
					}

					if (buffer_size < digestlen) {
						char *ptr;
						ptr = realloc(buffer, digestlen);
						if (!ptr) {
							osec_error("realloc: %m");
							free(buffer);
							exit(EXIT_FAILURE);
						}
						buffer = ptr;
					}

					for (i = 0; i < digestlen; ++i) {
						sscanf(digest + i * 2, "%02x", &h);
						buffer[i] = (unsigned char) h;
					}

					if (!osec_csum_append_value(name, namelen, buffer, digestlen, &local_rec))
						exit(EXIT_FAILURE);
				}

				if (!append_value(OVALUE_CSUM, local_rec.data, local_rec.offset, &rec))
					exit(EXIT_FAILURE);

				for (z = 0; z < chsum_count; ++z)
					free(chsum[z]);
				free(chsum);
				chsum = NULL;
				chsum_count = 0;

				free(local_rec.data);
				free(buffer);
			}

			if (F_ISSET(flags, FLAG_LINK)) {
				if (!S_ISLNK(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: symlink field for not symbolic link",
					           pathname, line_nr);

				if (!append_value(OVALUE_LINK, slink, (size_t) strlen(slink)+1, &rec))
					exit(EXIT_FAILURE);
				free(slink);
			}

			if (cdb_make_add(&cdbm, fname, (unsigned) strlen(fname)+1, rec.data, (unsigned) rec.offset) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);

			free(fname);
			flags = 0;
		}
		;

%%

int yyerror(const char *s)
{
	printf("txt2osec: %s:%d: %s\n", pathname, line_nr, s);
	return(0);
}

void print_help(int ret)
{
	printf("Usage: %s [options] <FILENAME> <DBFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -V, --version   print program version and exit;\n"
	       "  -h, --help      output a brief help message.\n"
	       "\n", program_invocation_short_name);
	exit(ret);
}

void print_version(void)
{
	printf("%s version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Modified by Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "\n"
	       "Copyright (C) 2010-2020  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
		program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	FILE *fp;
	int c, fd;
	char *dbname;

	const hash_type_data_t *old_hash = NULL, *new_hash = NULL;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'V' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long (argc, argv, "hV", long_options, NULL)) != -1) {
		switch (c) {
			case 'V':
				print_version();
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if ((argc - optind) != 2)
		print_help(EXIT_FAILURE);

	pathname = argv[optind++];
	dbname   = argv[optind];

	if ((fp = fopen(pathname, "r")) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "fopen");

	if ((fd = open(dbname, O_WRONLY | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbname);

	if (ftruncate(fd, 0) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: ftruncate", dbname);

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	rec.data = NULL;
	rec.len  = 0;

	yyin = fp;
	yyparse();

	free(rec.data);
	fclose(fp);

	if (hashnames != NULL) {
		if (!get_hashes_from_string(hashnames, strlen(hashnames), &new_hash, &old_hash))
			exit(EXIT_FAILURE);
		free(hashnames);
	} else {
		new_hash = get_hash_type_data_by_name("sha1", strlen("sha1"));
		old_hash = NULL;
	}

	current_db.primary_hashtype = new_hash;
	current_db.secondary_hashtype = old_hash;

	if (!write_db_metadata(&cdbm))
		exit(EXIT_FAILURE);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbname);

	return EXIT_SUCCESS;
}
