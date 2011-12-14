include common.mk
include Makefile.conf

LIB = evcoap

SRCS = evcoap.c
SRCS += evcoap-internal.c
SRCS += debug.c

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

include lib.mk

SUBDIR = test
include subdir.mk
