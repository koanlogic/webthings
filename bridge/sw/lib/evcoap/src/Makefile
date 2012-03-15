include common.mk
include ../../../Makefile.conf
-include ../../../Makefile.warns

LIB = evcoap

SRCS  = evcoap.c
SRCS += evcoap_opt.c
SRCS += evcoap_cli.c
SRCS += evcoap_srv.c
SRCS += evcoap_pdu.c
SRCS += evcoap_net.c
SRCS += evcoap_enums.c
SRCS += evcoap_base.c
SRCS += evcoap_flow.c
SRCS += evcoap_resource.c
SRCS += evcoap_observe.c
SRCS += evcoap_timer.c
SRCS += evcoap_filesys.c

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += -Wno-unused

ifdef SHLIB
  LDFLAGS += $(LIBU_LDFLAGS)
  LDFLAGS += $(LIBEVENT_LDFLAGS)
  CLEANFILES += *.so
  ifdef OS_DARWIN
    CLEANFILES += *.dylib
  endif   # OS_DARWIN
endif   # SHLIB

DPADD += $(LIBEVENT_LDADD)
DPADD += $(LIBU_LDADD)

include lib.mk
