#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# think.py — inference through ai-daemon: no API key, no network, no SDK.
#
# This is the whole client. One D-Bus call opens a session and hands back a
# socket; frames on the socket are `u32 be length | u8 kind | CBOR`. The
# daemon decides who you are (it asks the kernel, not you), what you may use,
# and how much — none of which appears in this file, which is the point.
#
# Needs two distro packages: python-gobject, python-cbor2.
#
#   $ python think.py "why is the sky blue?"
#   $ ai-run -- python think.py "and it works with the network gone"

import socket, struct, sys
import cbor2
from gi.repository import Gio, GLib

reply, fds = Gio.bus_get_sync(Gio.BusType.SYSTEM, None).call_with_unix_fd_list_sync(
    "io.github.agraves.AIDaemon1",
    "/io/github/agraves/AIDaemon1/Manager",
    "io.github.agraves.AIDaemon1.Manager",
    "CreateSession",
    GLib.Variant("(sa{sv})", ("default", {})),  # "default" is the machine's alias
    GLib.VariantType("(oh)"), Gio.DBusCallFlags.NONE, -1, None, None)
sock = socket.socket(fileno=fds.steal_fds()[reply.unpack()[1]])

def send(request):
    payload = cbor2.dumps(request)
    sock.sendall(struct.pack(">IB", len(payload), 1) + payload)

def receive():
    length, kind = struct.unpack(">IB", sock.recv(5, socket.MSG_WAITALL))
    return cbor2.loads(sock.recv(length, socket.MSG_WAITALL))

send({"op": "hello", "proto": 1})
hello = receive()["session"]
print(f"[{hello['model']}, you are {hello['identity']}]", file=sys.stderr)

prompt = " ".join(sys.argv[1:]) or "Say hello."
send({"op": "generate", "messages": [{"role": "user", "content": prompt}]})
while True:
    event = receive()
    if "tok" in event:
        print(event["tok"], end="", flush=True)
    elif "error" in event:
        sys.exit(f"{event['error']['code']}: {event['error']['message']}")
    elif event.get("done"):
        print()
        break
