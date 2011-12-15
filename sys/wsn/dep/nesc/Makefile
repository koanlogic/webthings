# $Id: Makefile,v 1.2 2010/07/12 07:30:59 tho Exp $

include common.mk
include ../Makefile.conf

XENO_TARBALL = nesc-1.3.1.tar.gz
XENO_FETCH_URI = http://tinyos.stanford.edu/tinyos-rpms/$(XENO_TARBALL)
XENO_CONF_FLAGS = --prefix=$(DESTDIR)
XENO_NO_PATCH = true

include xeno.mk

# avoid complaints about missing install (automake bug?)
build-hook-pre:
	cd nesc-1.3.1/ && ln -sf /usr/bin/install .
