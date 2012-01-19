SRCS = main

all:
	@for x in ${SRCS}; do \
        echo "Compiling $${x}.tex" ; \
        latex $${x}.tex 1>/dev/null ; \
        echo "Converting $${x}.dvi to pdf" ; \
        dvipdf $${x}.dvi 1>/dev/null ; \
	done

clean:
	rm -rf *.aux *.log *.lof *.lot *.toc *.pdf *.dvi *.idx *.bz2 *.out

zip: all
	for x in ${SRCS}; do \
	    bzip2 -9 -f $${x}.pdf ; \
    done
