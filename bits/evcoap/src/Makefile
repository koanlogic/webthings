include common.mk
include ../Makefile.conf

LIB = evcoap

SRCS = evcoap.c
SRCS += evcoap_opt.c
SRCS += evcoap_cli.c
SRCS += evcoap_pdu.c
SRCS += evcoap_net.c
SRCS += evcoap_enums.c

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

CFLAGS += -Wno-unused

include lib.mk
