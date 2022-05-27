#!/usr/bin/env python3

from sys import argv, stderr, stdout, version_info
from functools import partial
eprint = partial(print, file=stderr)

import io, types
from itertools import islice
from collections import deque
from collections.abc import Generator, Iterator, Iterable

class CodeGen:
    def __init__(self, *, sep=' ', end='\n', indent=4, level=0, max_width=80, file=stdout):
        self._sep, self._end, self._indent = sep, end, indent
        self._level, self.max_width, self._file = level, max_width, file
        self._line = None

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self._file.close()

    def _write(self, data):
        return self._file.write(data)

    @property
    def prefix(self):
        return self._sep * self._indent * self._level

    def println(self, line):
        if line:
            return self._write(self.prefix + line + self._end)
        else:
            return self._write(self._end)

    def newline(self):
        return self._write(self._end)

    def printitem(self, item):
        r = 0
        if self._line == None:
            self._line = self.prefix + item
        elif len(self._line) + len(item) > self.max_width:
            r = self._file.write(self._line + self._end)
            self._line = self.prefix + item
        else:
            self._line += ' ' + item

        return r

    def printitems(self, items):
        return sum(map(self.printitem, items))

    def flushitems(self):
        r = 0
        if self._line is not None:
            r = self._file.write(self._line + self._end)
            self._line = None
        return r

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value):
        if not isinstance(value, int):
            raise TypeError(f'parameter must be an int, not {type(N)}!')

        if value < 0:
            raise TypeError(f'level must be non-negative, not {value}!')

        self._level = value

    def indented(self, levels=1, **kwarg):
        return CodeGenIdentedContext(self, levels, **kwarg)

    def block(self, **kwarg):
        return CodeGenIdentedContext(self, 0, **kwarg)

    def indent(self, levels=1):
        self.level += levels

    def unindent(self, levels=1):
        self.level -= levels

    dedent = unindent
    exdent = unindent
    outdent = unindent

class CodeGenIdentedContext:
    def __init__(self, wrapped, levels=1, *, end=None):
        self.wrapped, self.levels, self.end = wrapped, levels, end

    def __enter__(self):
        self.wrapped.indent(self.levels)
        return self.wrapped

    def __exit__(self, exception_type, exception_value, traceback):
        self.wrapped.flushitems()
        self.wrapped.unindent(self.levels)
        if self.end: self.wrapped.println(self.end)

def _iter(iterable):
    if isinstance(iterable, Iterator): return iterable
    return iter(iterable)

def _gen(iterable):
    if isinstance(iterable, Generator): return iterable
    return __gen(iterable)

def __gen(iterable):
    for item in iterable: yield item

def group(iterable, n):
    r = []
    for item in iterable:
        r.append(item)
        if len(r) == n:
            yield r
            r = []
    yield r

def spliterator(iterable, n):

    if not isinstance(n, int): raise TypeError(f'n must be an int, not {type(n)}!')
    tail_ready = False

    if n >= 0:
        count = 0
        generator = _gen(iterable)

        def head():
            nonlocal count, tail_ready
            for item in generator:
                if count >= n: break
                count += 1
                yield item

            tail_ready = True

        def tail():
            if not tail_ready: raise IndexError('head must be consumed before tail')
            for item in generator: yield item
    else:
        n = 1 - n
        buf = deque()
        def head():
            for item in iterable:
                buf.append(item)
                if len(buf) < n: continue
                yield buf.popleft()

            nonlocal tail_ready
            tail_ready = True

        def tail():
            if not tail_ready: raise IndexError('head must be consumed before tail')
            for item in buf: yield item

    return head(), tail()
