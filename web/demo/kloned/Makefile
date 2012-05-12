include ../Makefile.conf

KLONE_VERSION = 3.0.0

ifdef WTDEMO_DEBUG
KLONE_CONF_ARGS += --enable_debug
endif

KLONE_CONF_ARGS += --disable_cxx
KLONE_CONF_ARGS += --install_daemon_only
KLONE_CONF_ARGS += --daemon_name="wtdemo"
KLONE_CONF_ARGS += --prefix=$(DESTDIR)

# to speed up dev
#KLONE_CONF_ARGS += --enable_fs

WEBAPP_DIR = $(CURDIR)/webapp

include klapp.mk

klapp.mk: ; wget -O $@ -c http://koanlogic.com/klone/klapp-2.0.0.mk

distclean: ;
