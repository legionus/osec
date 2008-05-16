.\" Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
.\"
.\" Additional documentation for the osec.
.\"
.\" This file is covered by the GNU General Public License,
.\" which should be included with osec as the file COPYING.

[NAME]
osec \- lightweight integrity checking system

[DESCRIPTION]
Osec also adds an ability of checking system for the dangerous files, e.g.
suid, sgid and world writeable

If you run osec under root acount, then this program will work under
non-privilegy user with only one extra capability 'dac_read_search',
so osec cannot damage any system file on internal errors.
