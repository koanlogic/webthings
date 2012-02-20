MAIN = main.tex
DOC = $(MAIN:.tex=.pdf)

$(DOC):
	pdflatex $(MAIN) -o $@

clean: ; rm -rf *.aux *.log *.lof *.lot *.toc *.pdf *.dvi *.idx *.bz2 *.out *.snm *.nav

zip: all ; bzip2 -9 -f $(DOC)
