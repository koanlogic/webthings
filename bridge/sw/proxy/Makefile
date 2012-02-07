include common.mk
include Makefile.conf

PROG = kink
SRCS = main.c

CFLAGS += -I../evcoap/include
CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += $(LIBEVCOAP_CFLAGS)

LDADD += ../evcoap/src/libevcoap.a
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

DPADD += $(LDADD)


include prog.mk
