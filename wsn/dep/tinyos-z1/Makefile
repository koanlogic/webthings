include common.mk
include ../Makefile.conf

FILE = tinyos-z1-2.1.1-15_i386.tar.gz

XENO_FETCH_URI = http://sourceforge.net/settings/mirror_choices?projectname=zolertia&filename=tinyos-z1-2.1.1/$(FILE)
XENO_NO_PATCH = true
XENO_NO_CONF = true
XENO_NO_BUILD = true
XENO_NO_INSTALL = true

include xeno.mk

install:
	cp -r z1/* $(DESTDIR) && \
	    mv $(DESTDIR)/motelist-z1 $(BINDIR)
