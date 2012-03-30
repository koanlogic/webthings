include common.mk
include ../../../Makefile.conf

PROG = runtest

SRCS += main.c
SRCS += common_tasks.c 
SRCS += kache_evcoap.c 

CFLAGS += -I$(SRCDIR)/src
CFLAGS += $(LIBEVCOAP_CFLAGS)
LDADD += ../../../lib/evcoap/src/libevcoap.a
LDADD += ../src/libkache.a

CFLAGS += $(LIBU_CFLAGS)
LDADD += $(LIBU_LDADD)
LDFLAGS += $(LIBU_LDFLAGS)

CFLAGS += $(LIBEVENT_CFLAGS)
LDADD += $(LIBEVENT_LDADD)
LDFLAGS += $(LIBEVENT_LDFLAGS)

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "test execution failed"
endif
