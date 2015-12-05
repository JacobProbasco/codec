CFLAGS+=-std=c11 -Wall -Wextra

CFLAGS+=-D_XOPEN_SOURCE
CFLAGS+=-D_DARWIN_SOURCE

.PHONY: clean debug

codec: decoder.c
codec: encoder.c

debug: CFLAGS+=-g
debug: codec


clean:
	-rm decoder *.o
	-rm decoder *.o
