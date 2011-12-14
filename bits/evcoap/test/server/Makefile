include ../../Makefile.conf

SRCS = main.c
PROG = coap-server

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += -I../..

LDADD += ../../libevcoap.a
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

DPADD += $(LDADD)

include prog.mk
