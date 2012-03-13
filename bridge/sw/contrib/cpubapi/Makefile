include common.mk
include ../../Makefile.conf

PROG = cpubapi
SRCS = main.c 

CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += $(LIBEVCOAP_CFLAGS)

LDADD += ../../lib/pubapi/src/libpubapi.a 
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

DPADD += $(LDADD)

include prog.mk
