Name: osec
Version: 1.2.4
Release: 1%{?dist}

Summary: Lightweight file permission checker
License: GPL3
Group: System/Base
Url: https://sourceforge.net/projects/o-security/
Packager: Alexey Gladkov <gladkov.alexey@gmail.com>

Source: osec-%version.tar

Requires: shadow-utils

Provides: mtree-sec = %version-%release
Obsoletes: mtree-sec

%define osec_statedir /var/lib/osec
%define osec_group osec
%define osec_user osec

# Automatically added by buildreq on Sat Apr 21 2007 (-bi)
BuildRequires: gcc help2man libcdb-devel libcap-devel
BuildRequires: autoconf automake

%package cronjob
Summary: General cron framework for osec
Requires: %name = %version-%release
Requires: %name-reporter
Group: System/Base

%package mailreport
Summary: Collection of reporters for osec
Group: System/Base
Provides: %name-reporter
Requires: %name = %version-%release
Requires: %name-cronjob
Requires: /bin/mail
Requires: coreutils

%description
This package contains osec program which performs files integrity check
by traversing filesystem and making human readable reports about changes
and found files/directories with suspicious ownership or permissions.

%description cronjob
This package contains a general framework for osec pipelines.

%description mailreport
This package contains a set of reporters to use with osec:
osec_reporter - creates human readable reports;
osec_mailer - send mail only if some changes was detected;
osec_rpm_reporter - additional filter for osec_reporter,
add name of rpm packages for files in report.

%prep
%setup -q

%build
./autogen.sh

%configure \
	--disable-werror

make %{?_smp_mflags}

%install
%makeinstall

cd %buildroot
#cron job file
mkdir -p -- etc/cron.daily
mv -- .%_datadir/osec.cron etc/cron.daily/osec
chmod 700 -- etc/cron.daily/osec

#configs
mkdir -pm700 -- etc/osec
mv -- etc/dirs.conf .%_datadir/pipe.conf etc/osec/
chmod 600 -- etc/osec/*.conf

#install directory for the databases
mkdir -p -- .%osec_statedir

rm -f .%_bindir/osec_rpm_reporter

%clean
rm -rf -- %buildroot

%pre
/usr/sbin/groupadd -r -f %osec_group
/usr/sbin/useradd -r -g %osec_group -d /dev/null -s /dev/null -n %osec_user >/dev/null 2>&1 ||:

%files
%doc ChangeLog NEWS README src/restore data/osec-recheck
%_bindir/osec
%_bindir/osec2txt
%_bindir/txt2osec
%_bindir/osec-migrade-db
%_mandir/man1/*

%files cronjob
%config(noreplace) /etc/cron.daily/osec
%defattr(600,root,root,700)
%config(noreplace) /etc/osec

%files mailreport
%_bindir/osec_mailer
%_bindir/osec_reporter
%attr(770,root,%osec_group) %osec_statedir

%changelog
* Wed Oct 14 2009 Alexey Gladkov <gladkov.alexey@gmail.com> 1.2.4-1
- Initial release for RedHat.
