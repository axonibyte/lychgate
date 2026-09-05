#!/usr/bin/env python3
"""A minimal Redfish AccountService mock for the BMC acceptance test.

Implements exactly what lychgate's bmc driver touches: GET and PATCH on one
account member, behind HTTP Basic auth. Not a general Redfish emulator — it
exists so the real lychgated, through its real curl transport, drives real
HTTP end to end. State lives in a JSON file so the test can inspect it.

Usage: redfish-mock.py <port> <state-file> <auth-user> <auth-pass> <account-id>
The state file is seeded with {"UserName": "...", "Enabled": bool}.
"""

import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
STATE = sys.argv[2]
AUTH_USER = sys.argv[3]
AUTH_PASS = sys.argv[4]
ACCOUNT_ID = sys.argv[5]
ACCOUNT_PATH = f"/redfish/v1/AccountService/Accounts/{ACCOUNT_ID}"


def load():
    with open(STATE) as f:
        return json.load(f)


def store(state):
    with open(STATE, "w") as f:
        json.dump(state, f)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # quiet

    def _authed(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode()
        except Exception:
            return False
        return decoded == f"{AUTH_USER}:{AUTH_PASS}"

    def _send(self, code, body=""):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if not self._authed():
            return self._send(401, '{"error":"unauthorized"}')
        if self.path != ACCOUNT_PATH:
            return self._send(404, '{"error":"not found"}')
        self._send(200, json.dumps(load()))

    def do_PATCH(self):
        if not self._authed():
            return self._send(401, '{"error":"unauthorized"}')
        if self.path != ACCOUNT_PATH:
            return self._send(404, '{"error":"not found"}')
        length = int(self.headers.get("Content-Length", "0"))
        patch = json.loads(self.rfile.read(length) or "{}")
        state = load()
        for key in ("UserName", "Password", "Enabled"):
            if key in patch:
                state[key] = patch[key]
        store(state)
        self._send(204)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
