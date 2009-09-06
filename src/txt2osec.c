/* txt2osec.c
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"
#include "osec.h"

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: txt2osec [options] <FILENAME>.txt [<DBFILE>]\n"
	       "\n"
	       "By default, DBFILE is <FILENAME> without '.txt' suffix.\n"
	       "\n"
	       "Options:\n"
	       "  -h, --help  output a brief help message.\n"
	       "\n");
	exit(ret);
}

static void __attribute__ ((noreturn))
print_version(void) {
        printf("txt2osec version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2009  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
        exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv) {
	FILE *fp;
	char *line = NULL, *dbfile = NULL, *infile = NULL;
	size_t len = 0;
	ssize_t nread;

	struct cdb_make cdbm;

	int line_end = 0;
	char *s, *d;

	int c, fd, i = 0;
	unsigned int h;

	unsigned char csum[digest_len];

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'v' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long (argc, argv, "hv", long_options, NULL)) != -1) {
		switch (c) {
			case 'v':
				print_version();
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if (optind == argc)
		print_help(EXIT_FAILURE);

	infile = argv[optind++];

	if ((fp = fopen(infile, "r")) == NULL)
		exit(EXIT_FAILURE);

	if (optind == argc) {
		len = (strlen(infile) - 4);
		if (strcmp((infile + len), ".txt") == 0) {
			dbfile = (char *) xmalloc(len+1);
			strncpy(dbfile, infile, len);
			dbfile[len+1] = '\0';
		}
		else {
			fclose(fp);
			fprintf(stderr, "ERROR: You must specifiy <DB-FILENAME>\n\n");
			print_help(EXIT_FAILURE);
		}
	}
	else
		dbfile = strdup(argv[optind]);

	if ((fd = open(dbfile, O_WRONLY | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbfile);

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	while ((nread = getline(&line, &len, fp)) != -1) {
		void *val = NULL;
		size_t vlen = 0;

		int found_csum = 0;
		char *fn = NULL, *slink = NULL;
		osec_stat_t ost;
		csum[0] = '\0';

		if (line[nread-1] == '\n')
			line[nread-1] = '\0';

		s = line;
		line_end = 0;

		while (!line_end) {
			if ((d = strchr(s, '\t')) == NULL)
				line_end = 1;
			else
				*d = '\0';

			if (strncmp(s, "file=", 5) == 0) {
				fn = s + 5;
			}
			else if (strncmp(s, "dev=", 4) == 0) {
				ost.dev = (dev_t) atoll(s + 4);
			}
			else if (strncmp(s, "ino=", 4) == 0) {
				ost.ino = (ino_t) atol(s + 4);
			}
			else if (strncmp(s, "mode=", 5) == 0) {
				if (sscanf(s+5, "%lo", (unsigned long *) &ost.mode) != 1) {
					fprintf(stderr, "Error: Unable parse mode\n");
					exit(1);
				}
			}
			else if (strncmp(s, "uid=", 4) == 0) {
				ost.uid = (uid_t) atol(s + 4);
			}
			else if (strncmp(s, "gid=", 4) == 0) {
				ost.gid = (gid_t) atol(s + 4);
			}
			else if (strncmp(s, "checksum=", 9) == 0) {
				s += 9;
				if (strlen(s) == (digest_len*2)) {
					for (i = 0; i < digest_len; i++) {
						sscanf(s, "%02x", &h);
						csum[i] = (unsigned char) h;
						s += 2;
					}
					found_csum = 1;
				}
			}
			else if (strncmp(s, "symlink=", 8) == 0) {
				slink = (s + 8);
			}
			else {
				continue;
			}
			s = (d + 1);
		}

		append_value(OVALUE_STAT, &val, &vlen, &ost, sizeof(ost));
		if (found_csum)
			append_value(OVALUE_CSUM, &val, &vlen, &csum, (size_t) digest_len);
		if (slink)
			append_value(OVALUE_LINK, &val, &vlen, slink, (size_t) strlen(slink)+1);

		if (cdb_make_add(&cdbm, fn, (unsigned) strlen(fn)+1, val, (unsigned) vlen) != 0)
			osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fn);

		xfree(val);
	}

	xfree(line);
	fclose(fp);

	write_db_version(&cdbm);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbfile);

	return 0;
}
