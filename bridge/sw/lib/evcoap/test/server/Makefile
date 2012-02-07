include common.mk
include ../../Makefile.conf

SRCS = main.c
PROG = coap-server

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

LDADD += ../../src/libevcoap.a
LDADD += ../../extra/src/libevcoap-extra.a
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

DPADD += $(LDADD)

include prog.mk
