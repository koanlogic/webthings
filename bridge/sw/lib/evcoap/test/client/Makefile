include common.mk
include ../../../../Makefile.conf
include ../Makefile.common

SRCS = main.c
PROG = coap-client

include prog.mk

ifdef OS_DARWIN
all-hook-post: ; /usr/bin/dsymutil $(PROG)
clean-hook-post: ; rm -rf $(PROG).dSYM
endif
