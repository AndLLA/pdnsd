
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)

.PHONY: all clean distclean

noinst_PROGRAMS = if_up is_local_addr tping random test_use_server

## Dirty trick:  I demand that these objects be built; then, with the knowledge
## that the object files will end up here, I redefine the link chain. 

TESTADDSRC=
#TESTADDSRC= netdev.c error.c thread.c helpers.c icmp.c
TESTDEPS = netdev.o error.o thread.o helpers.o icmp.o

TESTOBJS = netdev.o error.o thread.o helpers.o icmp.o

# Define dependencies for dns_query.c, which test_use_server.c will include
DNS_QUERY_EXTRA_OBJS = dns.o conff.o consts.o servers.o list.o cache.o debug.o
DNS_QUERY_ALL_OBJS = $(DNS_QUERY_EXTRA_OBJS) $(TESTOBJS) # Combine with existing TESTOBJS

if_up_SOURCES = if_up.c $(TESTADDSRC)
if_up_LDADD =  $(TESTOBJS) @thread_CFLAGS@
if_up_DEPENDENCIES = $(TESTDEPS)

is_local_addr_SOURCES = is_local_addr.c $(TESTADDSRC)
is_local_addr_LDADD = $(TESTOBJS) @thread_CFLAGS@
is_local_addr_DEPENDENCIES = $(TESTDEPS)

tping_SOURCES = tping.c $(TESTADDSRC)
tping_LDADD = $(TESTOBJS) @thread_CFLAGS@
tping_DEPENDENCIES = $(TESTDEPS)

random_SOURCES = random.c $(TESTADDSRC)
random_LDADD = $(TESTOBJS) @thread_CFLAGS@
random_DEPENDENCIES = $(TESTDEPS)

test_use_server_SOURCES = test_use_server.c
# test_use_server includes dns_query.c, so it needs its dependencies.
test_use_server_LDADD = $(DNS_QUERY_ALL_OBJS) @thread_CFLAGS@
test_use_server_DEPENDENCIES = $(DNS_QUERY_ALL_OBJS)

# These are Symlinks we want to have in the package
#EXTRA_DIST = conff.h error.h helpers.h icmp.h ipvers.h netdev.h thread.h cacheing

# Generic rule to build .o files from ../*.c (src directory)
# This covers both TESTOBJS and DNS_QUERY_EXTRA_OBJS
DEPS_OBJS = $(sort $(TESTOBJS) $(DNS_QUERY_EXTRA_OBJS))
$(DEPS_OBJS): %.o: ../%.c
	$(COMPILE) $(AM_CPPFLAGS) $(CPPFLAGS) $(CFLAGS) @thread_CFLAGS@ -c $<

# Ensure dns_query.c itself is not compiled into a separate .o for test_use_server target,
# as it will be #included in test_use_server.c.
# However, other objects it depends on (like dns.o, conff.o) must be built via DEPS_OBJS.
