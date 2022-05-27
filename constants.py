#!/usr/bin/env python3

from sys import argv, stderr, stdout, version_info
from functools import partial
eprint = partial(print, file=stderr)

from itertools import islice, starmap
from struct import iter_unpack
from codegen import CodeGen, group, spliterator

# based on https://possiblywrong.wordpress.com/2017/09/30/digits-of-pi-and-python-generators/
def pi_words():
    k, n, d = 1, 2, 15
    while True:
        # denominator polynomial
        dk = 512*k**4 + 1024*k**3 + 712*k**2 + 194*k + 15

        # numerator polynomial
        nk = 120*k**2 + 151*k + 47

        # update values
        n = 16 * n * dk + nk * d
        d *= dk
        nybble, n = divmod(n, d)

        # accumulate eight nybbles
        m = k & 0x07
        if m == 0:   yield (w << 4) + nybble
        elif m == 1: w = nybble
        else:        w = (w << 4) + nybble

        k += 1

w = pi_words()
p_box = list(islice(w, 18))
s_boxes = [islice(w, 256), islice(w, 256), islice(w, 256), islice(w, 256)]

def print_array_hex(c, array):
    initial, last = spliterator(array, -1)
    c.printitems(map(lambda x: f'0x{x:08x},', initial))
    c.printitem(f'0x{next(last):08x}')

c = CodeGen(indent=2)
c.println('#include "bcrypt-ext.h"')
c.println('#pragma GCC visibility push(internal)')
with c.block(end='#pragma GCC visibility pop') as c:
    # Magic IV for 64 Blowfish encryptions that we use to produce the 'hash'
    MAGIC = b'OrpheanBeholderScryDoubt'
    c.println('BF_word BF_magic_w[6] = {')
    with c.indented(end='};') as c:
        it = iter_unpack('>L', MAGIC)
        initial, last = spliterator(iter_unpack('>L', MAGIC), -1)
        c.printitems(starmap(lambda x: f'0x{x:08x},', initial))
        c.printitem(f'0x{next(last)[0]:08x}')

    c.println('BF_ctx BF_init_state = {')
    with c.indented(end='};') as c:
        c.println('{')

        with c.indented(end='}, {') as c:
            c.println('{')
            head, tail = spliterator(s_boxes, -1)

            for s_box in head:
                with c.indented(end='}, {') as c:
                    print_array_hex(c, s_box)

            for s_box in tail:
                with c.indented(end='}') as c:
                    print_array_hex(c, s_box)

        with c.indented(end='}') as c:
            print_array_hex(c, p_box)

