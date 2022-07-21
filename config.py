#!/usr/bin/env python3

from sys import argv, stderr, stdout, version_info
from functools import partial
eprint = partial(print, file=stderr)

import io
import re
from os import environ, getenv
from subprocess import run, Popen, check_output, CalledProcessError

libcache = {}
def libre(lib, pattern=None):
    p_in = f'#include <{lib}>\n'
    try:
        if lib in libcache:
            p = libcache[lib]
        else:
            p = check_output(['cpp'], input=p_in, encoding='utf-8', text=True)
            p = re.sub(r'^#.*?$', '', p, flags=re.M|re.S)
            p = re.sub(r',\s*\n\s*', ', ', p, flags=re.M|re.S)
            p = re.sub(r'\n+', '\n', p, flags=re.M|re.S)
            libcache[lib] = p

        m = re.search(pattern, p, flags=re.M|re.S)
        if m is not None:
            return True
    except CalledProcessError:
        pass

    return False

def funsig(return_type, name, arg_types):
    r = r'^' + return_type + r'\s+' + name + r'\s*\('

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

    r += r'\s*;'

    return r

def hasfun(lib, return_type, name, arg_types):
    regexp = funsig(return_type, name, arg_types)
    if libre(lib, regexp):
        print('#define HAS_' + name.upper() + '\n')
    else:
        print('#ifdef HAS_' + name.upper())
        print('#undef HAS_' + name.upper())
        print('#endif\n')

print('#pragma once')
hasfun('sys/random.h', 'ssize_t', 'getrandom', ('void *', 'size_t', 'unsigned int',))
