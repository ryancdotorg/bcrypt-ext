#!/usr/bin/env python3

from sys import argv, stderr, stdout, version_info
from functools import partial
eprint = partial(print, file=stderr)

import io
import re
from os import environ, getenv
from subprocess import check_call, check_output, DEVNULL, CalledProcessError

extensions = set()
libcache = {}
def libre(lib, pattern=None, extension=None):
    p_in = f'#include <{lib}>\n'
    try:
        if (lib, extension) in libcache:
            p = libcache[(lib, extension)]
        else:
            cpp = ['cc', '-E', '-x', 'c', '-']
            if extension is not None:
                cpp.append('-D' + extension)
            p = check_output(cpp, input=p_in, encoding='utf-8', text=True)
            p = re.sub(r'^#.*?$', '', p, flags=re.M|re.S)
            p = re.sub(r',\s*\n\s*', ', ', p, flags=re.M|re.S)
            p = re.sub(r'\n+', '\n', p, flags=re.M|re.S)
            p = re.sub(r'[)]\s*\n\s*__', ') __', p, flags=re.M|re.S)
            libcache[(lib, extension)] = p

        m = re.search(pattern, p, flags=re.M|re.S)
        if m is not None:
            return True
    except CalledProcessError:
        pass

    return False

def try_compile(d, p_in):
    try:
        gcc = ['cc', '-Werror', '-x', 'c', '-c', '-', '-o', '/dev/null']
        p = check_output(gcc, input=p_in, stderr=DEVNULL, encoding='utf-8', text=True)
        print('#define HAS_' + d + '\n')
    except CalledProcessError:
        print('#ifdef HAS_' + d)
        print('#undef HAS_' + d)
        print('#endif\n')

def funsig(return_type, name, arg_types):
    if return_type[-1] == '*':
        return_type = return_type[:-1] + r'\*\s*'
    else:
        return_type += r'\s+'

    r = r'^(extern\s+)?' + return_type + name + r'\s*\('

    n_args = len(arg_types)
    for arg_type in arg_types:
        n_args -= 1

        arg_type = re.sub(r'\s+', '\\\\s+', arg_type)
        if arg_type[-1] == '*':
            arg_type = arg_type[:-1] + r'\*\s*'
        else:
            arg_type += r'\s+'

        arg_type += r'\w+\s*'
        arg_type += r',\s*' if n_args else r'\)'
        r += arg_type

    r += r'\s*' # having a ; here causes problems with __attribute__

    return r

def hasfun(lib, return_type, name, arg_types, extension=None):
    regexp = funsig(return_type, name, arg_types)
    if libre(lib, regexp, extension):
        if extension is not None and extension not in extensions:
            print('#define ' + extension.replace('=', ' '))
            extensions.add(extension)
        print('#define HAS_' + name.upper() + '\n')
    else:
        print('#ifdef HAS_' + name.upper())
        print('#undef HAS_' + name.upper())
        print('#endif\n')

print('#pragma once')
try_compile('WEAK_SYMBOLS', '__attribute__((weak)) void _(void *x) { } void f(void *x) { _(x); }')
hasfun('sys/random.h', 'ssize_t', 'getrandom', ('void *', 'size_t', 'unsigned int',))
hasfun('string.h', 'void', 'explicit_bzero', ('void *', 'size_t',))
hasfun('string.h', 'void', 'memset_explicit', ('void *', 'size_t',))
