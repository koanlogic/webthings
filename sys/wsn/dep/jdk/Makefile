include common.mk
include ../Makefile.conf

FILE = jdk-6u30-linux-i586.bin

XENO_FETCH_URI = http://download.oracle.com/otn-pub/java/jdk/6u30-b12/$(FILE)
XENO_NO_UNZIP = true
XENO_NO_PATCH = true
XENO_NO_CONF = true
XENO_NO_BUILD = true
XENO_NO_INSTALL = true

include xeno.mk

install:
	cd dist && \
		sh $(FILE) -noregister && \
		cp -r jdk1.6.0_30/* $(DESTDIR)
