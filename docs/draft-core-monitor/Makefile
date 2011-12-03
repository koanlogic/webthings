TCLSH = /usr/bin/tclsh
XML2RFC = $(HOME)/bin/xml2rfc.tcl

XML = draft-core-monitor.xml
TXT = $(XML:.xml=.txt)

all: $(TXT)

%.txt: %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@

clean: ; $(RM) $(TXT)
