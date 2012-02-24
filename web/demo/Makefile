include Makefile.conf

# SUBDIR += dep
SUBDIR += kloned

include subdir.mk

DISTCLEANFILES = Makefile.conf
DISTCLEANFILES += wtdemo_conf.h
DISTCLEANFILES += kloned/webapp/etc/kloned.conf

# special post actions for 'distclean' and 'uninstall' targets
distclean-post: ; rm -f $(DISTCLEANFILES)
