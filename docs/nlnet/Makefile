MAIN = nlnet-prop.tex
DOC = $(MAIN:.tex=.pdf)
DEPS = kache.tex nlnet-prop.tex options.tex related.tex sys.tex

$(DOC): $(DEPS)
	# run twice for TOC generation
	pdflatex $(MAIN) -o $@
	pdflatex $(MAIN) -o $@


clean: ; rm -rf *.aux *.log *.lof *.lot *.toc *.pdf *.dvi *.idx *.bz2 *.out

zip: all ; bzip2 -9 -f $(DOC)
