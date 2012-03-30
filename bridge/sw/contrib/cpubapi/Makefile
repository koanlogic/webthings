include common.mk
include ../../Makefile.conf

PROG = cpubapi
SRCS = main.c 

CFLAGS += $(LIBEVCOAP_CFLAGS)
LDADD += ../../lib/pubapi/src/libpubapi.a 
LDFLAGS += -ldl -lpthread

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
