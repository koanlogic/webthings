include common.mk
include ../Makefile.conf

PROG = runtest

SRCS += main.c
SRCS += common_tasks.c 

CFLAGS += $(LIBU_CFLAGS)
CFLAGS += -I$(SRCDIR)/src

LDADD += $(LIBU_LDADD)
LDADD += $(SRCDIR)/src/libkache.a

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "test execution failed"
endif
