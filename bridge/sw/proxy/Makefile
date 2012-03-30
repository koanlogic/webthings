include common.mk
include ../Makefile.conf

PROG = kink
SRCS = main.c

CFLAGS += $(LIBEVCOAP_CFLAGS)
LDADD += ../lib/evcoap/src/libevcoap.a

CFLAGS += $(LIBU_CFLAGS)
ifndef SHLIB
  LDADD += $(LIBU_LDADD)
else
  LDFLAGS += $(LIBU_LDFLAGS)
endif

CFLAGS += $(LIBEVENT_CFLAGS)
ifndef SHLIB
  LDADD += $(LIBEVENT_LDADD)
else
  LDFLAGS += $(LIBEVENT_LDFLAGS)
endif

DPADD += $(LDADD)

include prog.mk
