include Makefile.conf

SUBDIR =
SUBDIR += etc
SUBDIR += jdk
SUBDIR += nesc
SUBDIR += tinyos
SUBDIR += tinyos-z1
SUBDIR += tinyos-tools

include subdir.mk

DISTCLEANFILES = Makefile.conf

# create destination directory (backing up old)
all-pre: 
	if [ -e $(DESTDIR) ]; then \
		rm -rf $(DESTDIR).old ; \
		mv $(DESTDIR) $(DESTDIR).old ; \
	fi
	mkdir -p $(DESTDIR)

# special post actions for 'distclean' target
distclean-post:	
	rm -f $(DISTCLEANFILES)

# install custom Z1 environment
install-post: 
	rm -f $(DISTCLEANFILES)
