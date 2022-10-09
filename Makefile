export LANG=C LC_ALL=C

CODEGEN = iv.c
HEADERS = config.h bcrypt-ext.h
OBJ_BCRYPT = blowfish.o memzero.o iv.o codec.o blake2b-ref.o

override CFLAGS += -O3 -fPIC \
	-Wall -Wextra -pedantic \
	-std=gnu11 -march=native -ggdb

COMPILE = $(CC) $(CFLAGS)

.PHONY: all clean _clean _nop
.PRECIOUS: %.o

all: bcrypt_ext_test libbcrypt-ext.so

bcrypt_ext_test: bcrypt_ext_test.o $(OBJ_BCRYPT)
	$(COMPILE) $^ -o $@

config.h: config.py
	python3 -B $< > $@

iv.c: codegen.py constants.py
	python3 -B constants.py > $@

libbcrypt-ext.so: $(OBJ_BCRYPT)
	$(COMPILE) -shared $^ -o $@

# fallback build rules
%.o: %.c %.h $(HEADERS)
	$(COMPILE) -c $< -o $@

%.o: %.c $(HEADERS)
	$(COMPILE) -c $< -o $@

%.so: %.o
	$(COMPILE) -shared $< -o $@

# hack to force clean to run first *to completion* even for parallel builds
# note that $(info ...) prints everything on one line
clean: _nop $(foreach _,$(filter clean,$(MAKECMDGOALS)),$(info $(shell $(MAKE) _clean)))
_clean:
	rm -rf iv.c config.h bcrypt_ext_test $(wildcard *.o) $(wildcard *.so) || /bin/true
_nop:
	@true
