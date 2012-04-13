include common.mk
include ../Makefile.conf

PROG = kink

ifndef EC_DEMO_ENABLE
  SRCS = main.c
else
  SRCS = demo.c
endif

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
