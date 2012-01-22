TXT = $(XML:.xml=.txt)

# check prerequisites
ifndef TCLSH
	$(error missing prerequisite: 'tclsh'!)
endif
ifndef XML2RFC
	$(error missing prerequisite: 'xm2rfc'!)
endif

all: $(TXT)

%.txt: %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@

clean: ; $(RM) $(TXT)
