# The tier-A C library. `make test` runs the shared-vector KAT harness on the
# host; `make avr-check` compiles every object for the ATmega328p, proving
# the code fits the tier (no linking — there is no app here, integrators
# wire lgse/lggrant/lghmac/lgcap into their sketch).
CC ?= cc
AVR_GCC ?= avr-gcc
# A dedicated variable: make's builtin CFLAGS default would silently win a ?=.
LGCFLAGS = -std=c99 -Wall -Wextra -Werror -O2

SRC = lychgate-se/sha256.c lychgate-se/lgse.c lychgate-se/lghmac.c \
      lychgate-se/lggrant.c lychgate-se/lgcap.c

.PHONY: test avr-check clean

test: build/kat_main
	LG_VECTORS=../wire/vectors ./build/kat_main

build/kat_main: $(SRC) lychgate-se/test/kat_main.c
	mkdir -p build
	$(CC) $(LGCFLAGS) -o $@ lychgate-se/test/kat_main.c $(SRC)

avr-check: $(SRC)
	mkdir -p build/avr
	for f in $(SRC); do \
	    $(AVR_GCC) -std=c99 -Wall -Wextra -Werror -Os -mmcu=atmega328p \
	        -c $$f -o build/avr/$$(basename $$f .c).o || exit 1; \
	done
	@echo "avr-check: all objects compile for atmega328p"

clean:
	rm -rf build
