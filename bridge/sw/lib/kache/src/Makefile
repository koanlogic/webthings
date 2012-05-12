include common.mk
include ../../../Makefile.conf

LIB = kache
SRCS = kache.c
SRCS += kache_obj.c
SRCS += kache_evcoap.c

CFLAGS += $(LIBU_CFLAGS)
DPADD += $(LIBU_LDADD)

CFLAGS += -Wno-unused

include lib.mk
