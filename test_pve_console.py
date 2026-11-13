#!/usr/bin/env python3
"""Tests for pve_console.py: frame codec round-trips, .vv emission,
argument handling. No network, no viewer, no PVE."""

import base64
import errno
import io
import os
import socket
import struct
import subprocess
import time
import unittest
from unittest import mock

import pve_console as pc


class FrameCodecTests(unittest.TestCase):
    """Client frames are masked with correct lengths; server frames parse."""

    def _server_frame(self, payload):
        n = len(payload)
        if n <= 125:
            header = bytes([0x82, n])
        elif n <= 0xFFFF:
            header = bytes([0x82, 126]) + struct.pack(">H", n)
        else:
            header = bytes([0x82, 127]) + struct.pack(">Q", n)
        return header + payload

    def _read_via(self, data):
        class FakeSock:
            def __init__(self):
                self.data = data

            def recv(self, n):
                out, self.data = self.data[:n], self.data[n:]
                return out

        return pc.WsReader(FakeSock())

    def test_client_frame_is_masked_and_length_correct(self):
        payload = os.urandom(200)  # 16-bit length form
        captured = {}

        class Sink:
            def sendall(self, data):
                captured["frame"] = data

        pc.ws_send_frame(Sink(), payload)
        frame = captured["frame"]
        self.assertEqual(frame[1] & 0x80, 0x80, "mask bit must be set")
        self.assertEqual(frame[1] & 0x7F, 126)
        self.assertEqual(struct.unpack(">H", frame[2:4])[0], len(payload))
        mask, body = frame[4:8], frame[8:]
        self.assertEqual(
            bytes(b ^ mask[i % 4] for i, b in enumerate(body)), payload)

    def test_server_payloads_round_trip(self):
        # Value: protects=the reader returns exactly the payload the server sent across every length form; fails_when=length parsing drifts from RFC 6455; why_new=no other test exercises the decoder; seam=none; no_claim=none beyond protects
        for size in (0, 1, 125, 126, 300):
            payload = os.urandom(size)
            fin, opcode, back = self._read_via(self._server_frame(payload)).frame()
            self.assertTrue(fin)
            self.assertEqual(opcode, 2)
            self.assertEqual(back, payload)

    def test_two_frames_split_across_one_recv(self):
        a, b = b"first", b"second"
        rd = self._read_via(self._server_frame(a) + self._server_frame(b))
        self.assertEqual(rd.frame()[1:], (2, a))
        self.assertEqual(rd.frame()[1:], (2, b))

    def test_masked_server_frame_refused(self):
        # Value: protects=the client rejects server frames carrying the RFC-forbidden mask bit; fails_when=a masked frame is accepted and its payload unmasked wrongly; why_new=server-frame validation was added to fail loud instead of forwarding garbage; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x82, 0x80 | 1, 0, 0, 0, 0]) + b"x")
        with self.assertRaises(ValueError):
            rd.frame()

    def test_rsv_bits_refused(self):
        # Value: protects=RSV bits are rejected because no extension was negotiated; fails_when=a frame with extensions is parsed as if plain; why_new=fail-loud protocol validation; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x82 | 0x40, 0x02]) + b"ab")
        with self.assertRaises(ValueError):
            rd.frame()

    def test_unknown_opcode_refused(self):
        # Value: protects=opcodes outside the data/control set are rejected instead of silently dropped; fails_when=an unknown opcode is swallowed; why_new=fail-loud protocol validation; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x83, 0x02]) + b"ab")
        with self.assertRaises(ValueError):
            rd.frame()

    def test_fragmented_control_frame_refused(self):
        # Value: protects=RFC 6455's fragmented-control-frame prohibition is enforced; fails_when=a fin=0 ping/pong/close is accepted; why_new=control frames must arrive whole; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x09, 0x02]) + b"pp")  # ping, fin=0
        with self.assertRaises(ValueError):
            rd.frame()

    def test_oversized_control_frame_refused(self):
        # Value: protects=control frames keep their 125-byte payload cap so our pong echoes stay legal; fails_when=a >125-byte ping is accepted and answered with an oversized pong; why_new=the echo path must not become a protocol violator; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x89, 126]) + struct.pack(">H", 130) + b"p" * 130)
        with self.assertRaises(ValueError):
            rd.frame()

    def test_ping_replies_with_pong_opcode(self):
        captured = {}

        class Sink:
            def sendall(self, data):
                captured["frame"] = data

        pc.ws_send_frame(Sink(), b"abc", 0xA)
        self.assertEqual(captured["frame"][0] & 0x0F, 0xA)
        # pong payloads are not masked on the server side, but the encoder is
        # the client's; the mask bit is harmless for the local loopback test.

    def test_oversized_frame_refused(self):
        header = bytes([0x82, 127]) + struct.pack(">Q", 64 * 1024 * 1024)
        rd = self._read_via(header)
        with self.assertRaises(ValueError):
            rd.frame()


    def test_expected_ws_accept_matches_rfc_example(self):
        # Value: protects=the upgrade response is verified against the RFC 6455 derivation, so a non-websocket endpoint cannot be mistaken for the session; fails_when=the accept computation drifts from the spec; why_new=no test covered the handshake verification; seam=none; no_claim=none beyond protects
        self.assertEqual(
            pc.expected_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


class VvEmissionTests(unittest.TestCase):
    # Value: protects=the .vv handed to the wrapper carries the bridge's local port and the full prefixed ticket; fails_when=the vv loses the ticket or points at the wrong port; why_new=the wrapper's own tests only cover .vvs built by cv4pve-vdi; seam=none (ws_connect mocked); no_claim=network behavior, websocket is mocked
    def test_vv_carries_ticket_and_local_port(self):
        captured = {}

        def fake_ws_connect(*args, **kwargs):
            return mock.Mock(), b""

        class Listener:
            def bind(self, a):
                pass

            def listen(self, n):
                pass

            def accept(self):
                raise RuntimeError("stop before pumps")

            def getsockname(self):
                return ("127.0.0.1", 45678)

            def close(self):
                pass

        def fake_open(path, mode="r", *a, **k):
            captured.setdefault("writes", []).append(
                captured.pop("pending", ""))
            return mock.mock_open()(path, mode, *a, **k)

        # simpler: intercept the written text through mock_open's handle
        m = mock.mock_open()
        with mock.patch.object(pc, "ws_connect", side_effect=fake_ws_connect), \
                mock.patch.object(pc.socket, "socket", return_value=Listener()), \
                mock.patch.object(pc.subprocess, "Popen", side_effect=RuntimeError("stop")), \
                mock.patch("builtins.open", m):
            args = mock.Mock(host="h", node="n", vmid=101, viewer=None)
            with self.assertRaises(RuntimeError):
                pc.bridge_and_launch({"port": "5900",
                                      "ticket": "PW:PVEVNC:rest"}, "cookie", args)
        written = "".join(c.args[0] for c in m().write.call_args_list)
        self.assertIn("port=45678", written)
        self.assertIn("password=PW:PVEVNC:rest", written)
        self.assertIn("type=vnc", written)
        self.assertIn("host=127.0.0.1", written)


class BridgeSetupTests(unittest.TestCase):
    """bridge_and_launch setup/pump behavior with mocked sockets and viewer."""

    # Value: protects=TCP_NODELAY is pinned on the accepted socket, fragmented server messages are reassembled before forwarding, stray continuations kill the session instead of corrupting the stream, and a viewer that dies pre-connect cannot hang the launcher; fails_when=a refactor drops the option, forwards fragments raw, or accepts forever; why_new=these setup behaviors had no coverage; seam=none (ws_connect/Popen/sockets mocked); no_claim=no real TLS, PVE, or viewer behavior

    def _run_bridge(self, tcp, accept_fn, reader):
        tcp.recv.side_effect = OSError("stop")  # tcp_to_ws exits at once
        viewer = mock.Mock()
        viewer.wait.return_value = 0
        with mock.patch.object(pc, "ws_connect", return_value=(mock.Mock(), b"")), \
                mock.patch.object(pc, "WsReader", return_value=reader), \
                mock.patch.object(pc.socket, "socket", return_value=self._listener(accept_fn)), \
                mock.patch.object(pc.subprocess, "Popen", return_value=viewer), \
                mock.patch("builtins.open", mock.mock_open()):
            args = mock.Mock(host="h", node="n", vmid=101, viewer=None,
                             validate_cert=True)
            pc.bridge_and_launch({"port": "5900",
                                  "ticket": "PW:PVEVNC:rest"}, "cookie", args)
        return tcp, viewer

    def _listener(self, accept_fn):
        class Listener:
            def bind(self, a):
                pass

            def listen(self, n):
                pass

            def getsockname(self):
                return ("127.0.0.1", 45678)

            def settimeout(self, t):
                pass

            def close(self):
                pass

            def accept(self):
                return accept_fn()

        return Listener()

    def _settle(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def test_nodelay_set_on_accepted_socket(self):
        reader = mock.Mock()
        reader.frame.side_effect = EOFError  # ws_to_tcp exits at once
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        tcp.setsockopt.assert_called_once_with(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def test_fragmented_message_reassembled_before_forwarding(self):
        reader = mock.Mock()
        reader.frame.side_effect = [
            (False, 2, b"AAA"),
            (True, 0, b"BBB"),
            EOFError,
        ]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.sendall.call_args_list))
        tcp.sendall.assert_called_once_with(b"AAABBB")

    def test_stray_continuation_terminates_session(self):
        reader = mock.Mock()
        reader.frame.side_effect = [(True, 0, b"junk"), EOFError]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        tcp.sendall.assert_not_called()

    def test_reassembly_is_capped(self):
        # Value: protects=reassembly cannot grow without bound on a hostile frame stream; fails_when=fragments accumulate past MAX_MESSAGE_BYTES; why_new=the per-frame 16 MiB limit does not bound a message; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (False, 2, b"A" * 4),
            (True, 0, b"B" * 8),
            EOFError,
        ]
        tcp = mock.Mock()
        with mock.patch.object(pc, "_WS_MAX_MESSAGE_BYTES", 8):
            tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        tcp.sendall.assert_not_called()

    def test_empty_first_fragment_reassembles(self):
        # Value: protects=an empty first fragment still counts as a started message; fails_when=buffer-emptiness is used as the reassembly sentinel; why_new=the sentinel regression would tear down legal sessions; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (False, 2, b""),
            (True, 0, b"x"),
            EOFError,
        ]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.sendall.call_args_list))
        tcp.sendall.assert_called_once_with(b"x")

    def test_overlapping_fragment_start_rejected(self):
        # Value: protects=a new fragmented message during reassembly aborts the session instead of silently discarding the partial one; fails_when=the partial message is overwritten and the viewer renders corrupt output; why_new=silent stream corruption class; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (False, 2, b"A"),
            (False, 2, b"B"),
            EOFError,
        ]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        tcp.sendall.assert_not_called()

    def test_econnaborted_accept_is_retried(self):
        # Value: protects=a transient ECONNABORTED during accept does not kill the session; fails_when=any accept OSError is treated as fatal; why_new=macOS aborts backlog entries that RST before accept; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        tcp = mock.Mock()
        accepted = []

        def accept():
            if not accepted:
                accepted.append(1)
                raise OSError(errno.ECONNABORTED, "connection aborted")
            return (tcp, ("127.0.0.1", 1))

        tcp, _ = self._run_bridge(tcp, accept, reader)
        tcp.setsockopt.assert_called_once_with(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def test_viewer_death_during_accept_raises(self):
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        viewer = mock.Mock()
        viewer.poll.return_value = 0  # viewer already dead

        def accept():
            raise socket.timeout()

        with mock.patch.object(pc, "ws_connect", return_value=(mock.Mock(), b"")), \
                mock.patch.object(pc, "WsReader", return_value=reader), \
                mock.patch.object(pc.socket, "socket", return_value=self._listener(accept)), \
                mock.patch.object(pc.subprocess, "Popen", return_value=viewer), \
                mock.patch("builtins.open", mock.mock_open()):
            args = mock.Mock(host="h", node="n", vmid=101, viewer=None,
                             validate_cert=True)
            with self.assertRaises(RuntimeError) as ctx:
                pc.bridge_and_launch({"port": "5900",
                                      "ticket": "PW:PVEVNC:rest"}, "cookie", args)
        self.assertIn("without connecting", str(ctx.exception))
        viewer.terminate.assert_called_once_with()


class WsConnectTests(unittest.TestCase):
    # Value: protects=the upstream socket disables Nagle before the TLS upgrade; fails_when=the option is dropped or moved after the handshake; why_new=the diff's first NODELAY call site had no coverage; seam=none (create_connection/ssl mocked); no_claim=no real TLS handshake

    def test_nodelay_set_before_tls_wrap(self):
        raw = mock.Mock()
        ctx = mock.Mock()
        ctx.wrap_socket.return_value = raw
        key = base64.b64encode(b"\x01" * 16).decode()
        accept = pc.expected_ws_accept(key)
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode()
        raw.recv.side_effect = [response]
        with mock.patch.object(pc.socket, "create_connection", return_value=raw), \
                mock.patch.object(pc.ssl, "create_default_context", return_value=ctx), \
                mock.patch.object(pc.os, "urandom", return_value=b"\x01" * 16):
            sock, rest = pc.ws_connect("h", 8006, "n", 1,
                                       {"port": "5900", "ticket": "T"},
                                       "cookie", validate_cert=False)
        self.assertIs(sock, raw)
        self.assertEqual(rest, b"")
        raw.setsockopt.assert_called_once_with(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # The option must be applied before any upgrade I/O happens.
        setsockopt_pos = raw.mock_calls.index(
            mock.call.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))
        sendall_pos = raw.mock_calls.index(mock.call.sendall(mock.ANY))
        self.assertLess(setsockopt_pos, sendall_pos,
                        "NODELAY must be set before the upgrade request")


class MintTests(unittest.TestCase):
    # Value: protects=the one-time VNC ticket never reaches stderr/logs on the mint failure path and missing pvesh keys fail with a diagnostic instead of a bare KeyError; fails_when=pvesh JSON is echoed or a missing key escapes unhandled; why_new=the failure path previously echoed ticket-bearing JSON; seam=none (ssh mocked); no_claim=no real ssh/pvesh behavior

    def _mint_with(self, stdout):
        with mock.patch.object(pc.subprocess, "check_output",
                               return_value=stdout):
            return pc.mint("h", "n", "1")

    def test_failure_path_does_not_echo_output(self):
        leaky = b'{"ticket":"SECRETONE","port":"5900"}'  # no ticket line
        with self.assertRaises(RuntimeError) as ctx:
            self._mint_with(leaky)
        self.assertNotIn("SECRETONE", str(ctx.exception))

    def test_missing_keys_fail_with_diagnostic(self):
        out = b'{"ticket":"T"}\nPVE:apiticket'  # port missing
        with self.assertRaises(RuntimeError) as ctx:
            self._mint_with(out)
        self.assertIn("port", str(ctx.exception))

    def test_success_returns_vnc_and_cookie(self):
        vnc, cookie = self._mint_with(b'{"port":"5900","ticket":"T"}\nPVE:apiticket')
        self.assertEqual(vnc["ticket"], "T")
        # The API cookie keeps its PVE: prefix; only the JSON body is parsed.
        self.assertEqual(cookie, "PVE:apiticket")

    # Regression: ISSUE-001 — ssh failures surfaced as a raw CalledProcessError
    # traceback instead of the one-line error contract.
    # Found by /qa on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=ssh dial/auth failures and pvesh hangs surface as a one-line RuntimeError; fails_when=CalledProcessError or TimeoutExpired escapes mint; why_new=probe 005 reproduced the traceback against an unreachable host; seam=none; no_claim=none beyond protects
    def test_ssh_failure_translates_to_runtime_error(self):
        with mock.patch.object(pc.subprocess, "check_output",
                               side_effect=subprocess.CalledProcessError(255, "ssh")), \
                self.assertRaises(RuntimeError) as ctx:
            pc.mint("h", "n", "1")
        self.assertIn("ssh", str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, subprocess.CalledProcessError)

    def test_ssh_timeout_translates_to_runtime_error(self):
        with mock.patch.object(pc.subprocess, "check_output",
                               side_effect=subprocess.TimeoutExpired("ssh", 30)), \
                self.assertRaises(RuntimeError) as ctx:
            pc.mint("h", "n", "1")
        self.assertIn("timed out", str(ctx.exception))


class ArgTests(unittest.TestCase):
    def test_missing_required_argument_exits(self):
        with self.assertRaises(SystemExit):
            pc.main(["--host", "h"])

    def test_minimal_triple_reaches_mint(self):
        # Value: protects=--host/--node/--vmid are all required and sufficient to reach minting; fails_when=argparse rejects a valid triple or ignores a required flag; why_new=contract for the CLI surface; seam=none; no_claim=none beyond protects
        # mint raises ValueError, which main does not translate, so it must
        # propagate to prove the flow reached minting (RuntimeError now maps
        # to the one-line exit-2 path).
        with mock.patch.object(pc, "mint", side_effect=ValueError("stop-here")), \
                mock.patch.object(pc.signal, "signal"), \
                self.assertRaises(ValueError) as ctx:
            pc.main(["--host", "h", "--node", "n", "--vmid", "1"])
        self.assertEqual(str(ctx.exception), "stop-here")

    def test_runtime_error_prints_one_line_and_exits_2(self):
        # Value: protects=minting/setup failures surface as a one-line diagnostic with exit 2, not a traceback; fails_when=RuntimeError escapes main; why_new=routine misconfigurations were stacking tracebacks on the wrapper's clean errors; seam=none; no_claim=none beyond protects
        with mock.patch.object(pc, "mint", side_effect=RuntimeError("boom")), \
                mock.patch.object(pc.signal, "signal"), \
                mock.patch("sys.stderr", new=io.StringIO()) as err:
            rc = pc.main(["--host", "h", "--node", "n", "--vmid", "1"])
        self.assertEqual(rc, 2)
        self.assertEqual(err.getvalue(), "error: boom\n")

    def test_validate_cert_alias_still_accepted(self):
        # Value: protects=the removed --validate-cert flag stays a silent no-op so persisted invocations keep working; fails_when=argparse rejects the old flag with exit 2 before any diagnostic; why_new=the flag's meaning equals the new default; seam=none; no_claim=none beyond protects
        with mock.patch.object(pc, "mint", side_effect=ValueError("stop-here")), \
                mock.patch.object(pc.signal, "signal"), \
                self.assertRaises(ValueError):
            pc.main(["--host", "h", "--node", "n", "--vmid", "1",
                     "--validate-cert"])


if __name__ == "__main__":
    unittest.main()
