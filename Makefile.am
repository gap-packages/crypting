#
# crypting: Hashes and Crypto in GAP
#
# This file is part of the build system of a GAP kernel extension.
# Requires automake.
#
ACLOCAL_AMFLAGS = -I m4

BINARCHDIR = bin/$(GAPARCH)
GAPINSTALLLIB = $(BINARCHDIR)/crypting.so

lib_LTLIBRARIES = crypting.la

crypting_la_SOURCES = src/crypting.c
crypting_la_CPPFLAGS = $(GAP_CPPFLAGS) -DCONFIG_H
crypting_la_LDFLAGS = -module -avoid-version
if SYS_IS_CYGWIN
crypting_la_LDFLAGS += -no-undefined -version-info 0:0:0 
crypting_la_LDFLAGS += -Wl,$(GAPROOT)/bin/$(GAPARCH)/gap.dll
endif

all-local: $(GAPINSTALLLIB)

$(GAPINSTALLLIB): crypting.la
	$(mkdir_p) $(BINARCHDIR)
if SYS_IS_CYGWIN
	cp .libs/crypting.dll $(GAPINSTALLLIB)
else
	cp .libs/crypting.so $(GAPINSTALLLIB)
endif

clean-local:
	rm -f $(GAPINSTALLLIB)

distclean-local:
	rm -rf bin/*

doc:
	($(GAPROOT)/bin/gap.sh -A makedoc.g)
