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
import errno
import hashlib
import json
import re
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
import time
import urllib.parse

# RFC 6455: control frame payloads are capped at 125 bytes. Both the pong
# producer and the parser enforce it so the echo path cannot become a
# protocol violator.
_WS_CONTROL_MAX = 125


# --------------------------------------------------------------------------
# websocket framing (RFC 6455, client side)
# --------------------------------------------------------------------------


def _disable_nagle(sock):
    # Interactive traffic (viewer input events) must not sit in Nagle's
    # buffer waiting for an ACK; framebuffer bulk is unaffected.
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def ws_send_frame(sock, payload, opcode=2):
    """Send one client frame; client frames are always masked."""
    mask = os.urandom(4)
    n = len(payload)
    if n <= _WS_CONTROL_MAX:
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
        """Return (fin, opcode, payload) for the next frame."""
        self._need(2)
        b1, b2 = self.buf[0], self.buf[1]
        if b1 & 0x70:
            raise ValueError("websocket RSV bits set (no extension negotiated)")
        if b2 & 0x80:
            raise ValueError("server frames must not be masked")
        opcode = b1 & 0x0F
        if opcode not in (0, 1, 2, 8, 9, 10):
            raise ValueError(f"unexpected websocket opcode {opcode}")
        if opcode >= 8 and not (b1 & 0x80):
            raise ValueError(f"fragmented control frame (opcode {opcode})")
        fin = bool(b1 & 0x80)
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
        if opcode >= 8 and n > _WS_CONTROL_MAX:
            raise ValueError(f"control frame payload {n} exceeds {_WS_CONTROL_MAX} bytes")
        self._need(off + n)
        payload = self.buf[off:off + n]
        self.buf = self.buf[off + n:]
        return fin, opcode, payload


# --------------------------------------------------------------------------
# PVE side: ticket mint over SSH, then the websocket upgrade
# --------------------------------------------------------------------------

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# One frame is capped at 16 MiB, but a fragmented message has no frame-level
# bound; this caps reassembly so a hostile server cannot grow the buffer
# without limit.
_WS_MAX_MESSAGE_BYTES = 64 * 1024 * 1024


def expected_ws_accept(key):
    """The Sec-WebSocket-Accept value a server must return for our key."""
    return base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()


def mint(host, node, vmid):
    """Mint a websocket VNC ticket plus an API session cookie over SSH."""
    try:
        out = subprocess.check_output(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "root@" + host,
             f"pvesh create /nodes/{shlex.quote(node)}/qemu/{vmid}/vncproxy"
             " --websocket 1 --output-format json; "
             "perl -MPVE::AccessControl -e 'print PVE::AccessControl::assemble_ticket(q(root@pam))'"],
            timeout=30,
        ).decode()
    except subprocess.CalledProcessError:
        # ssh's own diagnostic (unreachable, auth refused) is already on our
        # stderr; add the one-line contract error, not a traceback.
        raise RuntimeError(f"could not reach {host} over ssh to mint the ticket") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"ssh to {host} timed out minting the ticket") from None
    except UnicodeDecodeError:
        # Root banners or locale noise can carry non-UTF-8 bytes; the JSON and
        # ticket line are ASCII, so anything undecodable is junk around them.
        raise RuntimeError(f"ssh to {host} produced non-UTF-8 output") from None
    idx = out.find("\nPVE:")
    if idx < 0:
        # pvesh's JSON body contains the one-time ticket; echo nothing from it.
        raise RuntimeError(f"could not mint ticket on {host}: pvesh produced no ticket line")
    try:
        vnc = json.loads(out[:idx])
    except ValueError:
        # The ticket line without valid JSON means pvesh changed or broke; the
        # body may hold the ticket, so echo nothing.
        raise RuntimeError(f"pvesh on {host} returned a non-JSON ticket response") from None
    if not isinstance(vnc, dict):
        raise RuntimeError(f"pvesh on {host} returned unexpected JSON")
    missing = [k for k in ("port", "ticket") if not vnc.get(k)]
    if missing:
        raise RuntimeError(f"pvesh response is missing {', '.join(missing)}")
    return vnc, out[idx + 1:].strip()


def ws_connect(host, port, node, vmid, vnc, api_ticket, validate_cert):
    raw = socket.create_connection((host, port), timeout=10)
    _disable_nagle(raw)
    ctx = ssl.create_default_context()
    if validate_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
    else:
        # The root session cookie rides this connection; an unvalidated
        # certificate means a man in the middle could read it. Only reached
        # with explicit --insecure, because self-signed hosts are the norm
        # for PVE.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        print("warning: certificate validation off; the root session cookie "
              "is sent unvalidated (--insecure)", file=sys.stderr)
    try:
        sock = ctx.wrap_socket(raw, server_hostname=host)
    except ssl.SSLCertVerificationError:
        raise RuntimeError(
            f"TLS certificate validation failed for {host}; pass --insecure "
            "if the host uses a self-signed certificate") from None
    except ssl.SSLError as exc:
        # A non-certificate handshake failure (downgrade, cipher mismatch, a
        # plain-HTTP port) must not coach the user into disabling validation;
        # an active MITM could be the cause.
        raise RuntimeError(f"TLS handshake with {host} failed: {exc}") from None
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
        listener.close()
        sock.close()
        raise
    tcp = None
    try:
        # A viewer that exits without connecting must not hang the launcher:
        # poll it while waiting for the bridge connection. A connection that
        # aborts before accept (ECONNABORTED) is transient; keep waiting.
        listener.settimeout(1)
        while tcp is None:
            try:
                tcp, _ = listener.accept()
            except socket.timeout:
                if viewer.poll() is not None:
                    raise RuntimeError(
                        "viewer exited without connecting to the console bridge"
                    ) from None
            except OSError as exc:
                if exc.errno != errno.ECONNABORTED:
                    raise
                # A sustained abort flood must not spin the loop or hide a
                # dead viewer: back off briefly and keep checking it.
                if viewer.poll() is not None:
                    raise RuntimeError(
                        "viewer exited without connecting to the console bridge"
                    ) from None
                time.sleep(0.1)
        listener.settimeout(None)
        _disable_nagle(tcp)
        tcp.settimeout(None)
        print(f"console: VM {args.vmid} on 127.0.0.1:{local_port}", file=sys.stderr)

        def ws_to_tcp():
            # Reassembly state: frag_op is None whenever no fragmented
            # message is in progress. The buffer alone cannot be the sentinel
            # because a legal first fragment may be empty.
            try:
                frag_op = None
                frag = bytearray()
                while True:
                    fin, opcode, payload = reader.frame()
                    if opcode == 8:
                        break
                    if opcode == 9:
                        ws_send(payload, 0xA)
                        continue
                    if opcode == 10:
                        continue
                    if opcode in (1, 2):
                        if frag_op is not None:
                            # RFC 6455 5.4: only control frames may interleave
                            # with a fragmented message; accepting a complete
                            # data frame here would reorder server bytes.
                            raise ValueError(
                                "data frame during message reassembly")
                        if not fin:
                            frag_op, frag = opcode, bytearray(payload)
                            continue
                    elif opcode == 0:
                        if frag_op is None:
                            raise ValueError(
                                "continuation frame without a started message")
                        frag += payload
                        if len(frag) > _WS_MAX_MESSAGE_BYTES:
                            raise ValueError(
                                "fragmented message exceeds "
                                f"{_WS_MAX_MESSAGE_BYTES} bytes")
                        if not fin:
                            continue
                        payload, opcode = bytes(frag), frag_op
                        frag_op, frag = None, bytearray()
                    if payload:
                        tcp.sendall(payload)
            except ValueError as exc:
                # A protocol violation must be diagnosable, not silent: the
                # viewer just sees a dead socket otherwise.
                print(f"console: protocol error, ending session: {exc}",
                      file=sys.stderr)
            except (EOFError, OSError):
                pass
            finally:
                # The session is over from the server side; make sure the
                # viewer sees it too instead of freezing on its last
                # framebuffer.
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
        return viewer.wait()
    except BaseException:
        # The viewer is already running; any failure between launch and
        # steady state must not orphan it with the bridge still live.
        with contextlib.suppress(OSError):
            viewer.terminate()
        raise
    finally:
        # Teardown on every path: close the local socket first so the viewer
        # cannot be left painting a dead session, then the websocket.
        # shutdown before close so a pump parked in recv is reliably woken.
        # Signals are ignored from here so a repeat TERM/Ctrl-C cannot abort
        # the cleanup tail (the .vv unlink) halfway.
        _SHUTDOWN_STATE["tearing_down"] = True
        if tcp is not None:
            with contextlib.suppress(OSError):
                tcp.shutdown(socket.SHUT_RDWR)
        listener.close()
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        with contextlib.suppress(OSError):
            os.unlink(vv_path)
        with contextlib.suppress(OSError):
            os.rmdir(vv_dir)


_SHUTDOWN_STATE = {"tearing_down": False}


def _on_signal(signum, _frame):
    # A second signal while the teardown finally runs must not abandon the
    # remaining cleanup (the .vv unlink); ignore it instead.
    if _SHUTDOWN_STATE["tearing_down"]:
        return
    raise SystemExit(128 + signum)


def _node_name(value):
    # PVE node names are DNS-label shaped; validating here keeps the value
    # safe for both the ssh command and the HTTP request line.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}", value):
        raise argparse.ArgumentTypeError(f"invalid node name: {value!r}")
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", required=True, help="PVE host address")
    ap.add_argument("--node", required=True, type=_node_name, help="cluster node name")
    ap.add_argument("--vmid", required=True, type=int, help="VM id")
    ap.add_argument("--port", type=int, default=8006, help="pveproxy port")
    ap.add_argument("--viewer", default=None,
                    help="viewer binary (default: the wrapper's TigerVNC path)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate validation for self-signed PVE "
                         "hosts; the root session cookie then rides an "
                         "unvalidated connection")
    args = ap.parse_args(argv)

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    try:
        vnc, api_ticket = mint(args.host, args.node, args.vmid)
        args.validate_cert = not args.insecure
        return bridge_and_launch(vnc, api_ticket, args)
    except (RuntimeError, OSError) as exc:
        # Minting, connection, and setup failures are one-line diagnostics,
        # not tracebacks.
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
