<%
from random import choice
from random import randint
import six
import collections
import random
import re
import string
from pwnlib.context import LocalContext
%>
<%page args= "raw_bytes, avoid='none'"/>
<%docstring>
Execute encodes.
</%docstring>    
<%
    arch      = 'amd64'
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

    code = bytes(res)
%>
    ${code}