include common.mk
include ../../../../Makefile.conf

SRCS = main.c
PROG = coap-client

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

ifdef SHLIB
  LDFLAGS += -L../../src -levcoap
  LDFLAGS += $(LIBU_LDFLAGS)
  LDFLAGS += $(LIBEVENT_LDFLAGS)
else
  LDADD += ../../src/libevcoap.a
  LDADD += $(LIBEVENT_LDADD)
  LDADD += $(LIBU_LDADD)
endif

DPADD += $(LDADD)

include prog.mk

ifdef OS_DARWIN
all-hook-post: ; /usr/bin/dsymutil $(PROG)
clean-hook-post: ; rm -rf $(PROG).dSYM
endif
