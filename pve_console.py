#!/usr/bin/env python3
"""Open a PVE console in TigerVNC without cv4pve-vdi.

Why this exists: cv4pve-vdi's VncWebSocketBridge stops relaying viewer input
while the screen keeps updating, so its consoles render but accept no mouse
or keyboard. This launcher bridges the same websocket itself, stdlib only,
and launches cv4pve_tigervnc_wrapper for the viewer.

    ./pve_console.py --host pve.lan --node pve --vmid 101

Ticket minting uses SSH to the PVE host as root (an authorized key is
required); the websocket then carries the session cookie and the one-time
VNC ticket exactly as the PVE web console does.

  1. mint a websocket VNC ticket over SSH (pvesh vncproxy),
  2. connect the websocket to pveproxy's vncwebsocket endpoint,
  3. listen on a local port, write the .vv, and run the wrapper,
  4. relay bytes both ways until the viewer exits, then clean up.

Security properties inherited from the wrapper: the ticket never enters
argv, env, or logs; the .vv is deleted as soon as the wrapper reads it;
the local listener binds loopback only and accepts a single connection.
"""

import argparse
import base64
import hashlib
import json
import shlex
import os
import signal
import socket
import ssl
import struct
import subprocess
import sys
import contextlib
import tempfile
import threading
import urllib.parse

DEFAULT_VIEWER = "/Applications/TigerVNC.app/Contents/MacOS/vncviewer"


# --------------------------------------------------------------------------
# websocket framing (RFC 6455, client side)
# --------------------------------------------------------------------------


def ws_send_frame(sock, payload, opcode=2):
    """Send one client frame; client frames are always masked."""
    mask = os.urandom(4)
    n = len(payload)
    if n <= 125:
        header = bytes([0x80 | opcode, 0x80 | n])
    elif n <= 0xFFFF:
        header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + mask + masked)


class WsReader:
    """Parses unmasked server frames from a socket."""

    def __init__(self, sock, initial=b""):
        self.sock = sock
        self.buf = initial

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("websocket closed by server")
            self.buf += chunk

    def frame(self):
        """Return (opcode, payload) for the next frame."""
        self._need(2)
        b1, b2 = self.buf[0], self.buf[1]
        opcode = b1 & 0x0F
        n, off = b2 & 0x7F, 2
        if n == 126:
            self._need(4)
            n = struct.unpack(">H", self.buf[2:4])[0]
            off = 4
        elif n == 127:
            self._need(10)
            n = struct.unpack(">Q", self.buf[2:10])[0]
            off = 10
        if n > 16 * 1024 * 1024:
            raise ValueError(f"oversized websocket frame: {n}")
        self._need(off + n)
        payload = self.buf[off:off + n]
        self.buf = self.buf[off + n:]
        return opcode, payload


# --------------------------------------------------------------------------
# PVE side: ticket mint over SSH, then the websocket upgrade
# --------------------------------------------------------------------------

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def expected_ws_accept(key):
    """The Sec-WebSocket-Accept value a server must return for our key."""
    return base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()


def mint(host, node, vmid):
    """Mint a websocket VNC ticket plus an API session cookie over SSH."""
    out = subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "root@" + host,
         f"pvesh create /nodes/{shlex.quote(node)}/qemu/{vmid}/vncproxy"
         " --websocket 1 --output-format json; "
         "perl -MPVE::AccessControl -e 'print PVE::AccessControl::assemble_ticket(q(root@pam))'"],
        timeout=30,
    ).decode()
    idx = out.find("\nPVE:")
    if idx < 0:
        raise RuntimeError(f"could not mint ticket on {host}: {out[:120]!r}")
    return json.loads(out[:idx]), out[idx + 1:].strip()


def ws_connect(host, port, node, vmid, vnc, api_ticket, validate_cert):
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl.create_default_context()
    if validate_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    else:
        # The session cookie rides this connection; an unvalidated certificate
        # means a man in the middle could read it. Kept off by default because
        # self-signed hosts are the norm for PVE, same default as cv4pve-vdi.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        print("warning: certificate validation off; the session cookie is "
              "sent unvalidated", file=sys.stderr)
    sock = ctx.wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    q = urllib.parse.urlencode({"port": vnc["port"], "vncticket": vnc["ticket"]})
    request = (
        f"GET /api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?{q} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        f"Cookie: PVEAuthCookie={api_ticket}\r\n"
        "\r\n"
    )
    sock.sendall(request.encode())
    sock.settimeout(10)  # a stalled upgrade must not hang the launcher
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > 65536:
            raise RuntimeError("websocket upgrade response too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("EOF during websocket upgrade")
        buf += chunk
    sock.settimeout(None)  # only a confirmed session may block indefinitely
    head, _, rest = buf.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0].decode("latin-1")
    if " 101 " not in status:
        raise RuntimeError(f"websocket upgrade refused: {status}")
    accept = None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"sec-websocket-accept":
            accept = value.strip().decode("latin-1")
    if accept != expected_ws_accept(key):
        raise RuntimeError("websocket accept key mismatch")
    return sock, rest


# --------------------------------------------------------------------------
# local bridge and viewer launch
# --------------------------------------------------------------------------


def bridge_and_launch(vnc, api_ticket, args):
    sock, pending = ws_connect(args.host, args.port, args.node, args.vmid,
                               vnc, api_ticket, args.validate_cert)
    reader = WsReader(sock, pending)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    local_port = listener.getsockname()[1]

    vv_dir = tempfile.mkdtemp(prefix="pve-console-")
    vv_path = os.path.join(vv_dir, "console.vv")
    with open(vv_path, "w") as fh:
        fh.write("[virt-viewer]\ntype=vnc\nhost=127.0.0.1\n"
                 f"port={local_port}\npassword={vnc['ticket']}\n"
                 f"title=VNC: VM {args.vmid}\ndelete-this-file=1\n")

    wrapper = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "cv4pve_tigervnc_wrapper.py")
    env = dict(os.environ)
    if args.viewer:
        env["CV4PVE_TIGERVNC_VIEWER"] = args.viewer
    try:
        viewer = subprocess.Popen([sys.executable, wrapper, vv_path], env=env)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(vv_path)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)
        listener.close()
        sock.close()
        raise
    tcp = None
    try:
        tcp, _ = listener.accept()
    except OSError:
        viewer.terminate()
        with contextlib.suppress(OSError):
            os.unlink(vv_path)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)
        listener.close()
        sock.close()
        raise
    tcp.settimeout(None)
    print(f"console: VM {args.vmid} on 127.0.0.1:{local_port}", file=sys.stderr)

    def ws_to_tcp():
        try:
            while True:
                opcode, payload = reader.frame()
                if opcode == 8:
                    break
                if opcode == 9:
                    ws_send(payload, 0xA)
                    continue
                if opcode in (1, 2) and payload:
                    tcp.sendall(payload)
        except (EOFError, OSError):
            pass
        finally:
            # The session is over from the server side; make sure the viewer
            # sees it too instead of freezing on its last framebuffer.
            with contextlib.suppress(OSError):
                tcp.shutdown(socket.SHUT_RDWR)
            tcp.close()

    def tcp_to_ws():
        try:
            while True:
                data = tcp.recv(65536)
                if not data:
                    break
                ws_send(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                ws_send(b"", 8)

    ws_lock = threading.Lock()

    def ws_send(data, opcode=2):
        with ws_lock:
            ws_send_frame(sock, data, opcode)

    pumps = [threading.Thread(target=ws_to_tcp, daemon=True),
             threading.Thread(target=tcp_to_ws, daemon=True)]
    for t in pumps:
        t.start()
    try:
        return viewer.wait()
    finally:
        # Teardown on every path: close the local socket first so the viewer
        # cannot be left painting a dead session, then the websocket.
        with contextlib.suppress(OSError):
            tcp.shutdown(socket.SHUT_RDWR)
        listener.close()
        sock.close()
        with contextlib.suppress(OSError):
            os.unlink(vv_path)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True, help="PVE host address")
    ap.add_argument("--node", required=True, help="cluster node name")
    ap.add_argument("--vmid", required=True, type=int, help="VM id")
    ap.add_argument("--port", type=int, default=8006, help="pveproxy port")
    ap.add_argument("--viewer", default=None,
                    help="viewer binary (default: the wrapper's TigerVNC path)")
    ap.add_argument("--validate-cert", action="store_true",
                    help="validate the PVE TLS certificate (self-signed by default)")
    args = ap.parse_args(argv)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))

    vnc, api_ticket = mint(args.host, args.node, args.vmid)
    return bridge_and_launch(vnc, api_ticket, args)


if __name__ == "__main__":
    sys.exit(main())
