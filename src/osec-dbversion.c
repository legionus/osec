// SPDX-License-Identifier: GPL-3.0-only
/*
 * File: osec-dbversion.c
 *
 * Copyright (C) 2013-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"

struct database_metadata current_db = { 0 };

static void print_help(int ret)
{
	printf("Usage: %s [options] <DBFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -V, --version   print program version and exit;\n"
	       "  -h, --help      output a brief help message.\n"
	       "\n",
	       program_invocation_short_name);
	exit(ret);
}

static void print_version(void)
{
	printf("%s version " PACKAGE_VERSION "\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2013-2020  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	       program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int fd, c;
	char *dbname;

	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long(argc, argv, "hV", long_options, NULL)) != -1) {
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

	if ((argc - optind) != 1)
		print_help(EXIT_FAILURE);

	dbname = argv[optind];

	// Open old database
	errno = 0;
	if ((fd = open(dbname, OSEC_O_FLAGS)) != -1) {
		if (!compat_db_version(fd))
			osec_fatal(EXIT_FAILURE, 0, "%s: file not look like osec database", dbname);
	}

	printf("%d\n", current_db.version);

	return 0;
}
