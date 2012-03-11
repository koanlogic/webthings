include common.mk
include ../../../Makefile.conf
-include ../../../Makefile.warns

LIB = pubapi

SRCS  = pubapi.c s_sqlite.c sqlite3.c svc.c

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)

DPADD += $(LIBEVENT_LDADD)
DPADD += $(LIBU_LDADD)

CFLAGS += -Wno-unused

include lib.mk
