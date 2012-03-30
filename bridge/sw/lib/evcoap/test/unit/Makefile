include common.mk
include ../../../../Makefile.conf
include ../Makefile.common

PROG = runtest

SRCS += main.c
SRCS += options.c 
SRCS += dups.c 
SRCS += filesys.c 

include prog.mk

ifndef NO_RUN_TEST
all-hook-post:
	@./$(PROG) -o - || echo "unit test execution failed"
endif
