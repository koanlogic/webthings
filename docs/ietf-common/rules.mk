TXT = $(XML:.xml=.txt)

all: $(TXT)

%.txt: %.xml $(XML2RFC) ; $(TCLSH) $(XML2RFC) xml2rfc $< $@

clean: ; $(RM) $(TXT)
