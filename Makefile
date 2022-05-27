export LANG=C LC_ALL=C

CODEGEN = iv.c
HEADERS = bcrypt-ext.h

override CFLAGS += -O3 -fPIC \
	-Wall -Wextra -pedantic \
	-std=gnu11 -march=native -ggdb

COMPILE = $(CC) $(CFLAGS)

.PHONY: all clean _clean _nop
.PRECIOUS: %.o

all: iv.so

iv.c: codegen.py constants.py
	python3 -B constants.py > $@

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
	rm -rf $(wildcard *.o) $(wildcard *.so) || /bin/true
_nop:
	@true
