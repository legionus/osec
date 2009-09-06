/* osec2txt.c
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

void  *read_buf;
size_t read_bufsize;
int show_varname = 0;
int outfd;

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: osec2txt [options] <DBFILE> [<OUTFILE>]\n"
	       "\n"
	       "By default, OUTFILE is <DBFILE>.txt\n"
	       "\n"
	       "Options:\n"
	       "  -n, --varname   add field prefix to each value;\n"
	       "  -h, --help      output a brief help message.\n"
	       "\n");
	exit(ret);
}

static void __attribute__ ((noreturn))
print_version(void) {
        printf("osec2txt version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2009  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
        exit(EXIT_SUCCESS);
}

static void
show_digest(const char *dst) {
	int i = 0;
	while (i < digest_len)
		dprintf(outfd, "%02x", (unsigned char) dst[i++]);
}

static void
dump_record(int fd, char *key, void *rec, size_t rlen) {
	osec_stat_t *st;
	char *field;

	if ((st = osec_field(OVALUE_STAT, rec, rlen)) == NULL)
		osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'stat' from dbvalue\n", key);

#define show_field(V,F,A) \
	((show_varname) ? dprintf(fd,"%s=" F "\t",V,(A)) : dprintf(fd,F "\t",(A)))

	show_field("file", "%s", key);
	show_field("dev", "%lld", st->dev);
	show_field("ino", "%ld", st->ino);
	show_field("mode","%lo", (unsigned long) st->mode);
	show_field("uid", "%ld", (long) st->uid);
	show_field("gid", "%ld", (long) st->gid);

	if (show_varname)
		dprintf(fd, "checksum=");

	if (S_ISREG(st->mode)) {
		if ((field = (char *) osec_field(OVALUE_CSUM, rec, rlen)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'checksum' from dbvalue\n", key);
		show_digest(field);
	}
	dprintf(fd, "\t");

	if (show_varname)
		dprintf(fd, "symlink=");
	if (S_ISLNK(st->mode)) {
		if ((field = (char *) osec_field(OVALUE_LINK, rec, rlen)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "%s: osec_field: Unable to get 'symlink' from database value\n", key);
		dprintf(fd, "%s", field);
	}
	dprintf(fd, "\n");
}

int
main(int argc, char **argv) {
	int c, fd, rc;
	size_t klen;
	char *dbfile, *outfile = NULL, *key;
	unsigned cpos, dlen;
	struct cdb cdbm;
	void *data;

	struct option long_options[] = {
		{ "varname",		no_argument,		0, 'n' },
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'v' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long (argc, argv, "nhv", long_options, NULL)) != -1) {
		switch (c) {
			case 'n':
				show_varname = 1;
				break;
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

	dbfile = argv[optind++];

	// Open database
	if ((fd = open(dbfile, O_RDONLY | O_NOFOLLOW | O_NOCTTY)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbfile);

	if (cdb_init(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(cdbm)");

	if (optind == argc) {
		outfile = (char *) xmalloc(strlen(dbfile) + 5);
		sprintf(outfile, "%s.txt", dbfile);
	}
	else
		outfile = strdup(argv[optind]);

	if ((outfd = open(outfile, O_WRONLY | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", outfile);

	cdb_seqinit(&cpos, &cdbm);

	while((rc = cdb_seqnext(&cpos, &cdbm)) > 0) {
		klen = cdb_keylen(&cdbm);
		key = (char *) xmalloc((size_t) (klen + 1));

		if (cdb_read(&cdbm, key, klen, cdb_keypos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read(key)");

		if (key[0] != '/') {
			xfree(key);
			continue;
		}

		key[klen] = '\0';

		dlen = cdb_datalen(&cdbm);
		data = xmalloc((size_t) dlen);

		if (cdb_read(&cdbm, data, dlen, cdb_datapos(&cdbm)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read(data)");

		dump_record(outfd, key, data, dlen);

		xfree(data);
		xfree(key);
	}

	if (close(outfd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", outfile);

	xfree(outfile);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbfile);

	return EXIT_SUCCESS;
}
