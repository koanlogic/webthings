include common.mk
include ../Makefile.conf

FILE = tinyos-tools-1.4.0.tar.gz

XENO_FETCH_URI = http://tinyos.stanford.edu/tinyos-rpms/$(FILE)
XENO_NO_PATCH = true
XENO_NO_CONF = true
XENO_NO_BUILD = true
XENO_NO_INSTALL = true

include xeno.mk

install:
	cp -r tinyos-tools-1.4.0/* $(DESTDIR) && \
	    cd $(DESTDIR)/tools && \
	    ln -s /usr/bin/install . && \
	    ./Bootstrap && \
	    ./configure --prefix=$(DESTDIR) && \
	    make && \
	    make install
