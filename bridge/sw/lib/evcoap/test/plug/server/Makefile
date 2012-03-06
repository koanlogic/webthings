include common.mk
include ../../../../../Makefile.conf

SRCS = main.c
PROG = coap-server

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

LDADD += ../../../src/libevcoap.a
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

DPADD += $(LDADD)

include prog.mk

ifdef OS_DARWIN
all-hook-post: ; /usr/bin/dsymutil $(PROG)
endif
