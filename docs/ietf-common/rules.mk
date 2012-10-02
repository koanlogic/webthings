TXT = $(XML:.xml=.txt)
HTML = $(XML:.xml=.html)

# check prerequisites
ifndef TCLSH
	$(error missing prerequisite: 'tclsh'!)
endif
ifndef XML2RFC
	$(error missing prerequisite: 'xm2rfc'!)
endif
ifndef RFCMARKUP
	$(error missing prerequisite: 'rfcmarkup'!)
endif

all: $(TXT) post

post: ; cp $(TXT) ~/Sites/ && $(RFCMARKUP) url=http://localhost/~$(shell whoami)/$(TXT) > ~/Sites/$(HTML)

%.txt: %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@

clean: ; $(RM) $(TXT)
