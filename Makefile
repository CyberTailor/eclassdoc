CFLAGS ?= -O2 -ggdb -W -Wall -Wextra -Wmissing-prototypes -Wstrict-prototypes -Wwrite-strings -Wno-unused-parameter
CFLAGS += $(shell pkg-config --cflags zlib)
LDFLAGS += $(shell pkg-config --libs zlib)

MANS	= mquery.1 \
	  mquery-function.1 \
	  mquery-variable.1

all: mquery mquery-function mquery-variable

mquery: mquery.o libmandoc.a
	$(CC) -o $@ $(LDFLAGS) $@.o libmandoc.a

mquery-function: mquery
	ln -f mquery $@

mquery-variable: mquery
	ln -f mquery $@

tags: mquery.c
	ctags -R >tags mquery.c /usr/include/mandoc

clean:
	rm -f mquery mquery-function mquery-variable mquery.o tags

.PHONY: all clean
