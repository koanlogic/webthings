include common.mk
include ../../../Makefile.conf

PROG = runtest

SRCS += main.c
SRCS += common_tasks.c 
SRCS += kache_evcoap.c 

CFLAGS += -I$(SRCDIR)/src
CFLAGS += $(LIBEVCOAP_CFLAGS)
ifndef SHLIB
  LDADD += ../../../lib/evcoap/src/libevcoap.a
  LDADD += ../src/libkache.a
endif

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

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "test execution failed"
endif
