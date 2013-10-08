TXT = $(XML:.xml=.txt)
HTML = $(XML:.xml=.html)

ifndef XML2RFC
	$(error missing prerequisite: 'xm2rfc'!)
endif
ifndef RFCMARKUP
	$(error missing prerequisite: 'rfcmarkup'!)
endif

all: $(TXT) post

post: ; cp $(TXT) ~/web/I-Ds/ && $(RFCMARKUP) url=http://localhost/~$(shell whoami)/I-Ds/$(TXT) > ~/web/I-Ds/$(HTML)

%.txt: %.xml $(XML2RFC) ; $(XML2RFC) $< $@

clean: ; $(RM) $(TXT)
