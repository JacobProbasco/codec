CFLAGS+=-std=c11 -Wall -Wextra -pedantic

CFLAGS+=-D_XOPEN_SOURCE
CFLAGS+=-D_DARWIN_SOURCE

.PHONY: clean debug

codec: decoder.c

debug: CFLAGS+=-g
debug: codec


clean:
	-rm codec *.o
