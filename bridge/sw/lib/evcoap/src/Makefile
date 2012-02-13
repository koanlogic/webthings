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

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

DPADD += $(LIBEVENT_LDADD)
DPADD += $(LIBU_LDADD)

CFLAGS += -Wno-unused

include lib.mk
