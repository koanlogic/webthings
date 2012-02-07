include common.mk
include ../../../../Makefile.conf

PROG = runtest

SRCS += main.c
SRCS += options.c 
SRCS += dups.c 
SRCS += filesys.c 

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)
#CFLAGS += -I$(SRCDIR)/src

LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

LDADD += ../../src/libevcoap.a
LDADD += ../../extra/libevcoap-extra.a

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "unit test execution failed"
endif
