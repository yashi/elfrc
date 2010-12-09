CFLAGS+=-Wall -O -pipe
VERSION=0.7

all: elfrc

elfrc: elfrc.o
	${CC} -o elfrc elfrc.o

elfrc.o: config.h

config.h:
	@rm -f config.h
	@echo "#ifndef __`uname`__" > config.h
	@echo "#  define __`uname`__ 1" >> config.h
	@echo "#endif" >> config.h
	@echo "#define ELFRC_VERSION \"${VERSION}\"" >> config.h

check:
	cd testdata && make check

dist: clean
	cd .. && \
		rm -rf elfrc-${VERSION} && \
		mkdir elfrc-${VERSION} && \
		for FILE in Makefile README LICENSE elfrc.c; do \
			cp -f elfrc/$$FILE elfrc-${VERSION}; \
		done && \
		rm -f elfrc-${VERSION}.tar.gz && \
		tar vzcf elfrc-${VERSION}.tar.gz elfrc-${VERSION} && \
		rm -rf elfrc-${VERSION} && \
		cd elfrc

clean:
	rm -f elfrc.o config.h elfrc

