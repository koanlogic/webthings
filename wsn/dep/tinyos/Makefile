include common.mk
include ../Makefile.conf

FILE = tinyos-2.1.1.tar.gz

XENO_FETCH_URI = http://tinyos.stanford.edu/tinyos-rpms/$(FILE)
XENO_NO_PATCH = true
XENO_NO_CONF = true
XENO_NO_BUILD = true
XENO_NO_INSTALL = true

include xeno.mk

build-hook-pre:
	cd tinyos-2.1.1/ && ln -s /usr/bin/install .

install:
	cp -r tinyos-2.1.1/* $(DESTDIR)
