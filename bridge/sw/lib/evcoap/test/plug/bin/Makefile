include ../../../../../Makefile.conf

REDIRECT=
ifndef EC_PLUG_VERBOSE
	REDIRECT=2>/dev/null
endif

all:
ifdef EC_PLUG_DUMP
	@EC_PLUG_DUMP=1 ./run.sh $(REDIRECT)
else
	@./run.sh $(REDIRECT)
endif

install uninstall depend cleandepend clean: ;
