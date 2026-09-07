#!/usr/bin/env python3
# A minimal HTTP "device" for http-acceptance.sh: one maintenance flag,
# flipped by POST and reported by GET, persisted to a state file the test
# greps — the ground truth oracle, separate from anything the daemon claims.
#
# Usage: http-device-mock.py <port> <state-file>

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
STATE_FILE = sys.argv[2]


def read_state():
    with open(STATE_FILE) as f:
        return json.load(f)


def write_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/api/maint":
            return self._reply(404, "{}")
        self._reply(200, json.dumps(read_state()))

    def do_POST(self):
        if self.path != "/api/maint":
            return self._reply(404, "{}")
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._reply(400, '{"error": "bad json"}')
        state = read_state()
        state["debug_uart"] = bool(body.get("debug_uart", False))
        write_state(state)
        self._reply(200, json.dumps(state))


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
