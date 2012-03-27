include common.mk
include ../../../Makefile.conf


PROG = runtest

SRCS += main.c
SRCS += common_tasks.c 
SRCS += kache_evcoap.c 

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += -I$(SRCDIR)/src

CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += $(LIBEVCOAP_CFLAGS)

LDADD += ../../../lib/evcoap/src/libevcoap.a
LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)
LDADD += ../src/libkache.a

LDFLAGS += $(LIBEVENT_LDFLAGS)

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "test execution failed"
endif
