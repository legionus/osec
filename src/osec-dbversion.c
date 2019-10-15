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

char *progname = NULL;

static void __attribute__((noreturn))
print_help(int ret)
{
	printf("Usage: %s [options] <DBFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -V, --version   print program version and exit;\n"
	       "  -h, --help      output a brief help message.\n"
	       "\n",
	       progname);
	exit(ret);
}

static void __attribute__((noreturn))
print_version(void)
{
	printf("%s version " PACKAGE_VERSION "\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2013  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
	       progname);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int fd, c;
	char *dbname;

	struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'V' },
		{ 0, 0, 0, 0 }
	};

	progname = basename(argv[0]);

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

	printf("%d\n", dbversion);

	return 0;
}
