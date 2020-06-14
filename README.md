# Osec is a lightweight integrity checking system.

You can use it to see difference between two states of your system
Osec also adds an ability of checking system for the dangerous files, e.g.
suid, sgid and world writeable

If you run osec under root acount, then this program will work under
non-privilegy user with only one extra capability `dac_read_search`, so osec
cannot damage any system file on internal errors.

The project contains the following utilities:

- `osec` -- data gathering program. Osec have made it's output in row
  format to stdout.

- `osec_reporter` -- report filter. You can pass row output from osec to reporter
  to see human-readable reports with some analisys.

- `osec2txt` -- converts the osec database to text format.

- `txt2osec` -- сreates a database from a text view.

Reporter process made it's output to stdout, so you can continue this pipeline.
For example, you can send e-mail with report to system administrator.

If you develop some interesting reporter module or filter you can sent to
authors to include it into osec distribution.

## Requires

You need following tools to build library:
- c compiler (gcc 3.2 or higher)
- libcdb library (0.76 or higher). Latest version available at http://www.corpit.ru/mjt/tinycdb.html
- libcap library (1.10 or higher)
- GNU autoconf (2.61 or higher)
- GNU automake (1.11 or higher)
- GNU help2man (1.40.12 or higher)
- libgcrypt

## Notes

You can use osec under non-privilege user, but if you try to run osec under
administrator account, osec will try to drop its privileges to non-privilege
user "osec". You can change this default user (and group) using --user (--group)
options.  By default, osec will create database in current directory. You can
change this path using --dbpath option. If you run osec under administrator
account please check that non privilege user have write osec in this output
directory.

## Bug reporting

Please report all bugs you find in the program directly to authors.

## Authors

Written in C++ by Stanislav Ievlev <inger@altlinux.org>.
Almost completely rewritten from scratch in C by Alexey Gladkov <gladkov.alexey@gmail.com>.
Support for hash type switching and stribog512 hash is implemented by Aleksei Nikiforov <darktemplar@basealt.ru>
