<%
from pwnlib.shellcraft.amd64.linux import encode
from pwnlib import asm
from pwnlib.shellcraft import amd64
%>
<%page args="code, flex=None"/>
<%docstring>
Execute a different process.

    >>> p = run_assembly(shellcraft.flexshell())
    >>> p.sendline(b'echo Hello')
    >>> p.recv()
    b'Hello\n'

</%docstring>
<%
    if "nobinsh" in flex:
        avoid = b'/bin/sh\x00'
    if "nonull" in flex:
        avoid = b'\x00'    
%>
${encode(code, avoid)}