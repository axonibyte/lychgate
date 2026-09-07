#!/usr/bin/env python3
# A pty-backed "device" for serial-acceptance.sh: opens a pty pair, announces
# the slave path, and answers a three-command maintenance protocol on the
# master side. State goes to a file the test greps — the ground truth oracle.
#
# Usage: serial-mock.py <workdir>
#   writes <workdir>/pts        (the slave tty path for the inventory)
#          <workdir>/state.json ({"maint": true|false})

import json
import os
import sys

WORK = sys.argv[1]

master, slave = os.openpty()
with open(os.path.join(WORK, "state.json"), "w") as f:
    json.dump({"maint": False}, f)
# Announce last, so the path only exists once state.json does.
with open(os.path.join(WORK, "pts"), "w") as f:
    f.write(os.ttyname(slave))

state = {"maint": False}


def save():
    with open(os.path.join(WORK, "state.json"), "w") as f:
        json.dump(state, f)


buf = b""
while True:
    buf += os.read(master, 256)
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        cmd = line.decode(errors="replace").strip()
        if cmd == "maint on":
            state["maint"] = True
            save()
            os.write(master, b"OK MAINT ON\n")
        elif cmd == "maint off":
            state["maint"] = False
            save()
            os.write(master, b"OK MAINT OFF\n")
        elif cmd == "maint?":
            os.write(
                master,
                b"MAINT ON\n" if state["maint"] else b"MAINT OFF\n",
            )
        else:
            os.write(master, b"ERR\n")
