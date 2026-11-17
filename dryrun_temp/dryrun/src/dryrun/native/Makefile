# Build the LD_PRELOAD shim used by dryrun's trace engine.
#
# The Python engine (dryrun.simulate.trace) compiles this same source with
# identical flags into a content-addressed cache; this Makefile exists for
# local development (`make`, `make clean`) and mirrors those flags exactly.

ifeq ($(origin CC),default)
CC = gcc
endif
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS = -ldl -lpthread

all: shadowlib.so

shadowlib.so: shadowlib.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< $(LDLIBS)

clean:
	rm -f shadowlib.so

.PHONY: all clean
