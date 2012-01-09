include common.mk
include ../../Makefile.conf

PROG = runtest

SRCS += main.c
SRCS += options.c 
SRCS += dups.c 

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += $(LIBEVENT_CFLAGS)
CFLAGS += -I$(SRCDIR)/src

LDADD += $(LIBEVENT_LDADD)
LDADD += $(LIBU_LDADD)

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "unit test execution failed"
endif
