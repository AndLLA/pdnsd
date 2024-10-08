# rpmbuild spec file for pdnsd.
# with modifications by Paul Rombouts.

# Supported rpmbuild --define and --with options include:
#
# --with isdn                   Configure with --enable-isdn.
#
# --without poll                Configure with --disable-poll
#
# --without nptl                Configure with --with-thread-lib=linuxthreads.
#
# --with ipv6                   Configure with --enable-ipv6.
#
# --without tcpqueries          Configure with --disable-tcp-queries.
#
# --without debug 	        Configure with --with-debug=0.
#
# --define "distro <distro>" 	Configure with --with-distribution=<distro>.
#
# --define "run_as_user <user>" Configure with --with-default-id=<user>.
#                               For RPMs the default <user> is "nobody".
#
# --define "run_as_uid <uid>" 	If the user defined by the previous option does not exist
#                               when the RPM is installed, the pre-install script will try
#                               to create a new user with numerical id <uid>.
#
# --define "cachedir <dir>" 	Configure with --with-cachedir=<dir>.
#

%{!?distro: %define distro Generic}

# The default run_as ID to use
%{!?run_as_user: %define run_as_user nobody}
# By default, if a new run_as_user is to be created, we let
# useradd choose the numerical uid, unless run_as_uid is defined.
#define run_as_uid 96
%{!?cachedir: %define cachedir /var/cache/pdnsd}
%define conffile %{_sysconfdir}/pdnsd.conf

Summary: A caching dns proxy for small networks or dialin accounts
Name: pdnsd
Version: 1.2.9a
Release: par
License: GPLv3
Group:  Daemons
Source: http://members.home.nl/p.a.rombouts/pdnsd/releases/%{name}-%{version}-%{release}.tar.gz
URL: http://members.home.nl/p.a.rombouts/pdnsd.html
Vendor: Paul A. Rombouts
Packager:  Paul A. Rombouts <p.a.rombouts@home.nl>
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
pdnsd is a proxy DNS daemon with permanent (disk-)cache and the ability
to serve local records. It is designed to detect network outages or hangups
and to prevent DNS-dependent applications like Netscape Navigator from hanging.

The original author of pdnsd is Thomas Moestl, but pdnsd is no longer maintained
by him. This is an extensively revised version by Paul A. Rombouts.
For a description of the changes see http://members.home.nl/p.a.rombouts/pdnsd.html
and the file README.par in %{_docdir}/%{name}-%{version}

%{!?distro:You can specify the target distribution when you build the source RPM. For instance, if you're building for a Red Hat system call rpmbuild with:}
%{!?distro:  --define "distro RedHat"}
%{?distro:This package was built for a %{distro} distribution.}
%{!?_with_isdn:It's possible to rebuild the source RPM with isdn support using the rpmbuild option:}
%{!?_with_isdn:  --with isdn}
%{?_with_isdn:This package was built with isdn support enabled.}
%{!?_with_ipv6:It's possible to rebuild the source RPM with ipv6 support using the rpmbuild option:}
%{!?_with_ipv6:  --with ipv6}
%{?_with_ipv6:This package was built with ipv6 support.}
%{?_without_poll:This package was built with the select(2) function instead of poll(2).}

%prep
%setup

%build
CFLAGS="${CFLAGS:-$RPM_OPT_FLAGS -Wall}" ./configure \
	--prefix=%{_prefix} --sysconfdir=%{_sysconfdir} --mandir=%{_mandir} \
	--with-cachedir="%{cachedir}" \
	%{?distro:--with-distribution=%{distro}} --enable-specbuild \
	--with-default-id=%{run_as_user} \
	%{?_with_isdn:--enable-isdn} \
	%{?_without_poll:--disable-poll} \
	%{?_without_nptl:--with-thread-lib=linuxthreads} \
	%{?_with_ipv6:--enable-ipv6} \
	%{?_without_tcpqueries:--disable-tcp-queries} \
	%{?_without_debug:--with-debug=0}

make

%install
%if "%{run_as_user}" != "nobody"
[ "$(id -un)" != root ] ||
id -u %{run_as_user} > /dev/null 2>&1 ||
/usr/sbin/useradd -c "Proxy DNS daemon" %{?run_as_uid:-u %{run_as_uid}} \
	-s /sbin/nologin -r -d "%{cachedir}" %{run_as_user} || {
  set +x
  echo "Cannot create user \"%{run_as_user}\"%{?run_as_uid: with uid=%{run_as_uid}}"
  echo "Please select another numerical uid and rebuild with --define \"run_as_uid uid\""
  echo "or create a user named \"%{run_as_user}\" by hand and try again."
  exit 1
}
%endif

rm -rf "$RPM_BUILD_ROOT"
make DESTDIR="$RPM_BUILD_ROOT" install
cp -f file-list.base file-list
find doc contrib -not -type d -not -iname '*makefile' -not -name '*.am' \
                 -not -name '*.in' -not -path 'doc/*.pl' |
sed -e 's/^/%doc --parents /'  >> file-list
CURDIR=$PWD; cd "$RPM_BUILD_ROOT"
find . -not -type d '(' -not -name 'pdnsd.conf*' -or -name 'pdnsd.conf.[1-9]*' ')' \
       -not -path '.%{_docdir}/*' -not -path './var/*' |
sed -e 's/^\.//
        \:/man:{
          /\.gz$/!s/$/.gz/
        }'  >> "$CURDIR/file-list"

%clean
rm -rf "$RPM_BUILD_ROOT"
#rm -rf %{_builddir}/%{name}-%{srcver}

%files -f file-list

%pre
# First stop any running pdnsd daemons
%if "%{distro}" == "SuSE"
/sbin/init.d/pdnsd stop >/dev/null 2>&1
%endif
%if "%{distro}" == "RedHat"
if [ -f /var/lock/subsys/pdnsd ]; then
  if /sbin/pidof pdnsd > /dev/null; then
    /sbin/service pdnsd stop >/dev/null 2>&1
    if [ "$1" -ge 2 ]; then touch /var/lock/subsys/pdnsd; fi
  else
    rm -f /var/lock/subsys/pdnsd
  fi
fi
%endif

%if "%{run_as_user}" != "nobody"
# Add the "pdnsd" user
id -u %{run_as_user} > /dev/null 2>&1 ||
/usr/sbin/useradd -c "Proxy DNS daemon" %{?run_as_uid:-u %{run_as_uid}} \
	 -s /sbin/nologin -r -d "%{cachedir}" %{run_as_user} || {
  echo "Cannot create user \"%{run_as_user}\"%{?run_as_uid: with uid=%{run_as_uid}}"
  echo "Please create a user named \"%{run_as_user}\" by hand and try again."
  exit 1
}
[ "$(id -gn %{run_as_user})" = %{run_as_user} ] || {
  echo "user \"%{run_as_user}\" does not have an corresponding group called \"%{run_as_user}\""
  echo "Please change the initial group of user \"%{run_as_user}\" to \"%{run_as_user}\" and try again."
  exit 1
}

if [ -f "%{conffile}" ] &&
    grep -v -e '^[[:blank:]]*\(#\|\/\/\)'  "%{conffile}" |
    grep -q -e '\<run_as[[:blank:]]*=[[:blank:]]*"\?nobody"\?[[:blank:]]*;'
then
    echo "An existing pdnsd configuration file %{conffile} has been detected, containing the run_as user ID \"nobody\""
    echo "For security reasons it is recommended that pdnsd run as a seperate user \"%{run_as_user}\""
    mv -f "%{conffile}" "%{conffile}.rpmsave" &&
    echo "Your original %{conffile} has been saved as %{conffile}.rpmsave" &&
    sed -e '/^[[:blank:]]*\(#\|\/\/\)/!s/\(\<run_as[[:blank:]]*=[[:blank:]]*\)"\?nobody"\?[[:blank:]]*;/\1"%{run_as_user}";/g' \
         "%{conffile}.rpmsave" > "%{conffile}" &&
    echo "In %{conffile} runs_as=\"nobody\" has been replaced by run_as=\"%{run_as_user}\""
fi
%endif

if [ -f "%{cachedir}/pdnsd.cache" ]; then
    chown -c %{run_as_user}:%{run_as_user} "%{cachedir}/pdnsd.cache"
fi

%post
%if "%{distro}" == "SuSE"
if [ -w /etc/rc.config ]; then
  grep "START_PDNSD" /etc/rc.config > /dev/null
  if [ $? -ne 0 ] ; then
    echo -e \
"\n\n#\n# Set to yes to start pdnsd at boot time\n#\nSTART_PDNSD=yes" \
>> /etc/rc.config
  fi
fi
%endif
%if "%{distro}" == "RedHat"
if [ "$1" = 1 ]; then
  /sbin/chkconfig --add pdnsd
fi
%endif

%preun
%if "%{distro}" == "RedHat"
if [ "$1" = 0 ]; then
  /sbin/service pdnsd stop >/dev/null 2>&1
  /sbin/chkconfig --del pdnsd
fi
%endif

%postun
%if "%{distro}" == "RedHat"
if [ "$1" -ge 1 ]; then
  /sbin/service pdnsd condrestart >/dev/null 2>&1
fi
%endif

%changelog
* Tue Jan 31 2012 Paul A. Rombouts <p.a.rombouts@home.nl>
- Prevent makefiles and perl scripts from being installed
  in the documentation directory.
* Sat Jan 28 2012 Paul A. Rombouts <p.a.rombouts@home.nl>
- Update the (Source) URLs.
* Sat Aug  4 2007 Paul Rombouts <p.a.rombouts@home.nl>
- License is now GPL version 3
* Fri Mar 24 2006 Paul Rombouts <p.a.rombouts@home.nl>
- Instead of using a fixed default value for run_as_uid,
  I let useradd choose the uid if run_as_uid is undefined.
* Thu Dec 29 2005 Paul Rombouts <p.a.rombouts@home.nl>
- TCP-query support is now compiled in by default,
  but can be disabled using "--without tcpqueries".
* Sun Jul 20 2003 Paul Rombouts <p.a.rombouts@home.nl>
- Changed default run_as ID from "nobody" to "pdnsd"
* Fri Jun 20 2003 Paul Rombouts <p.a.rombouts@home.nl>
- Added configuration option for NPTL.
* Sat Jun 07 2003 Paul Rombouts <p.a.rombouts@home.nl>
- Added automatic definition of distro using _vendor macro.
* Thu May 22 2003 Paul Rombouts <p.a.rombouts@home.nl>
- Ensured that modification times of acconfig.h and configure.in
  are not changed by patching to avoid unwanted reconfigure during make phase.
* Tue May 20 2003 Paul Rombouts <p.a.rombouts@home.nl>
- Applied my customized patch file. See READ.par for details.
* Sun May 16 2001 Thomas Moestl <tmoestl@gmx.net>
- Make use of chkconfig for Red Hat (patch by Christian Engstler)
* Sun Mar 25 2001 Thomas Moestl <tmoestl@gmx.net>
- Merged SuSE fixes by Christian Engstler
* Fri Feb 09 2001 Thomas Moestl <tmoestl@gmx.net>
- Merged in a spec fix for mapage inclusion contributed by Sourav K.
  Mandal
* Sun Nov 26 2000 Thomas Moestl <tmoestl@gmx.net>
- Added some patches contributed by Bernd Leibing
* Tue Aug 15 2000 Thomas Moestl <tmoestl@gmx.net>
- Added the distro for configure
* Tue Jul 11 2000 Sourav K. Mandal <smandal@mit.edu>
- autoconf/automake modifications
