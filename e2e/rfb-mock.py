#!/usr/bin/env python3
"""A bare TCP acceptor standing in for a bhyve RFB server.

It accepts and immediately closes connections so the vnc tunnel's reachability
can be probed end to end. It speaks no RFB: the acceptance proves the forward
is reachable and the password commands ran, NOT real RFB authentication nor the
one-client rule (see TESTING.md).

Usage: rfb-mock.py <port>
"""
import socket
import sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(16)
while True:
    try:
        conn, _ = s.accept()
        conn.close()
    except Exception:
        break
