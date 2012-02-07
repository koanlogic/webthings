include common.mk
include ../../../Makefile.conf

LIB = evcoap-extra
SRCS = evcoap_filesys.c

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

DPADD += $(LIBEVENT_LDADD)
DPADD += $(LIBU_LDADD)

ifndef EVCOAP_EXTRA
  NO_INSTALL = true
endif

include lib.mk
