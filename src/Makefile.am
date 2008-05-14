WARNINGS = -Wall -Wextra -Werror -W -Wshadow -Wpointer-arith -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization 

AM_CPPFLAGS = -g -std=c99 -D_BSD_SOURCE -D_GNU_SOURCE \
	$(WARNINGS)

AM_CPPFLAGS += -I./mozilla-sha1

bin_PROGRAMS = osec
osec_SOURCES = osec.c common.c memory.c privs.c status.c digest.c \
		./mozilla-sha1/sha1.c
osec_LIBS = -lcap -lcdb
