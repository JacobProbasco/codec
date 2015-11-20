CFLAGS+=-std=c11 -Wall -Wextra -pedantic -Werror

CFLAGS+=-D_XOPEN_SOURCE

.PHONY: clean debug

codec: decoder.c

debug: CFLAGS+=-g
debug: codec


clean:
	-rm codec *.o
