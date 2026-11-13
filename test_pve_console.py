#!/usr/bin/env python3
"""Tests for pve_console.py: frame codec round-trips, .vv emission, bridge
setup/pump behavior (reassembly, accept loop, protocol violations), ws_connect
TLS wiring, the mint error contract, and argument handling. No network, no
viewer, no PVE."""

import base64
import errno
import io
import os
import socket
import ssl
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

    def test_sixtyfour_k_payload_round_trip(self):
        # Value: protects=the 64-bit length form decodes payloads past the 16-bit boundary; fails_when=the 127-header path drifts (it was only ever exercised on its rejection path); why_new=round-trip sizes stopped at 300 bytes, so a 64k payload was never parsed; seam=none; no_claim=none beyond protects
        payload = os.urandom(65536)
        frame = bytes([0x82, 127]) + struct.pack(">Q", len(payload)) + payload
        fin, opcode, back = self._read_via(frame).frame()
        self.assertTrue(fin)
        self.assertEqual((opcode, back), (2, payload))

    def test_fin_flag_reflects_header_bit(self):
        # Value: protects=fin is read from the header bit so pump reassembly sees the server's fragmentation; fails_when=fin is hardcoded or inverted and fragments are forwarded raw; why_new=pump tests feed (fin, opcode, payload) tuples directly, so the parser's fin extraction had no data-frame test; seam=none; no_claim=none beyond protects
        rd = self._read_via(bytes([0x02, 0x03]) + b"abc")  # fin=0, binary
        self.assertEqual(rd.frame(), (False, 2, b"abc"))


    def test_expected_ws_accept_matches_rfc_example(self):
        # Value: protects=the upgrade response is verified against the RFC 6455 derivation, so a non-websocket endpoint cannot be mistaken for the session; fails_when=the accept computation drifts from the spec; why_new=no test covered the handshake verification; seam=none; no_claim=none beyond protects
        self.assertEqual(
            pc.expected_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


class VvEmissionTests(unittest.TestCase):
    # Value: protects=the .vv handed to the wrapper carries the bridge's local port and the full prefixed ticket, and a viewer-launch failure runs the cleanup branch; fails_when=the vv loses the ticket, points at the wrong port, or the OSError cleanup stops closing sockets; why_new=the wrapper's own tests only cover .vvs built by cv4pve-vdi, and the cleanup branch lost a duplicated rmdir in this diff; seam=none (ws_connect mocked); no_claim=network behavior, websocket is mocked
    def test_vv_carries_ticket_and_local_port(self):
        captured = {}
        closes = []

        ws_sock = mock.Mock()

        def fake_ws_connect(*args, **kwargs):
            return ws_sock, b""

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
                closes.append("listener")

        def fake_open(path, mode="r", *a, **k):
            captured.setdefault("writes", []).append(
                captured.pop("pending", ""))
            return mock.mock_open()(path, mode, *a, **k)

        # simpler: intercept the written text through mock_open's handle
        m = mock.mock_open()
        with mock.patch.object(pc, "ws_connect", side_effect=fake_ws_connect), \
                mock.patch.object(pc.socket, "socket", return_value=Listener()), \
                mock.patch.object(pc.subprocess, "Popen", side_effect=OSError("no viewer")), \
                mock.patch("builtins.open", m):
            args = mock.Mock(host="h", node="n", vmid=101, viewer=None)
            with self.assertRaises(OSError):
                pc.bridge_and_launch({"port": "5900",
                                      "ticket": "PW:PVEVNC:rest"}, "cookie", args)
        written = "".join(c.args[0] for c in m().write.call_args_list)
        self.assertIn("port=45678", written)
        self.assertIn("password=PW:PVEVNC:rest", written)
        self.assertIn("type=vnc", written)
        self.assertIn("host=127.0.0.1", written)
        # The Popen-OSError cleanup branch closed the listener and websocket.
        self.assertIn("listener", closes)
        ws_sock.close.assert_called_once_with()


class BridgeSetupTests(unittest.TestCase):
    """bridge_and_launch setup/pump behavior with mocked sockets and viewer."""

    # Value: protects=TCP_NODELAY is pinned on the accepted socket, fragmented server messages are reassembled before forwarding, stray continuations kill the session instead of corrupting the stream, and a viewer that dies pre-connect cannot hang the launcher; fails_when=a refactor drops the option, forwards fragments raw, or accepts forever; why_new=these setup behaviors had no coverage; seam=none (ws_connect/Popen/sockets mocked); no_claim=no real TLS, PVE, or viewer behavior

    def setUp(self):
        # bridge_and_launch's finally arms the teardown flag; a leaked value
        # would make the signal-handler test order-dependent.
        pc._SHUTDOWN_STATE["tearing_down"] = False

    def _run_bridge(self, tcp, accept_fn, reader, viewer=None, recv=None):
        # recv: optional list driving tcp_to_ws (defaults to dying at once).
        tcp.recv.side_effect = recv if recv is not None else OSError("stop")
        if viewer is None:
            viewer = mock.Mock()
            viewer.poll.return_value = None  # alive for the accept-loop check
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

    def test_accept_timeout_with_live_viewer_keeps_waiting(self):
        # Value: protects=an accept timeout with a live viewer keeps polling instead of killing the session; fails_when=the first timeout is treated as viewer death; why_new=only the dead-viewer timeout path had a test; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        tcp = mock.Mock()
        viewer = mock.Mock()
        viewer.poll.return_value = None  # viewer alive
        attempts = []

        def accept():
            attempts.append(1)
            if len(attempts) == 1:
                raise socket.timeout()
            return (tcp, ("127.0.0.1", 1))

        tcp, _ = self._run_bridge(tcp, accept, reader, viewer=viewer)
        self.assertEqual(len(attempts), 2)
        tcp.setsockopt.assert_called_once_with(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def test_accept_fatal_oserror_terminates_viewer_and_propagates(self):
        # Value: protects=a fatal accept error tears down the just-launched viewer instead of orphaning it with a live bridge; fails_when=the OSError escapes without terminate() or teardown; why_new=only the ECONNABORTED-retry and dead-viewer paths had tests; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        viewer = mock.Mock()

        def accept():
            raise OSError(errno.EINVAL, "broken listener")

        with self.assertRaises(OSError):
            self._run_bridge(mock.Mock(), accept, reader, viewer=viewer)
        viewer.terminate.assert_called_once_with()

    def test_unfragmented_data_messages_relayed_to_viewer(self):
        # Value: protects=complete server messages (binary and text) reach the viewer untouched; fails_when=the rewritten pump forwards only fragments or drops text frames; why_new=the pump's core relay path had no test (only fragment/EOF/error paths); seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (True, 2, b"AAA"),
            (True, 1, b"BBB"),
            EOFError,
        ]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(
            lambda: len(tcp.sendall.call_args_list) == 2))
        self.assertEqual(
            [c.args[0] for c in tcp.sendall.call_args_list], [b"AAA", b"BBB"])

    def test_server_close_frame_ends_session_without_forwarding(self):
        # Value: protects=the server's close frame ends the bridge and frees the viewer instead of being treated as data; fails_when=opcode 8 payload reaches tcp.sendall or the pump spins forever; why_new=session end via close frame is the normal PVE teardown and had no pump test; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [(True, 8, b"")]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        tcp.sendall.assert_not_called()

    def test_server_ping_answered_with_pong(self):
        # Value: protects=server pings are answered with exactly one pong and server pongs are swallowed so the PVE keepalive neither starves nor corrupts the bridge; fails_when=a ping is forwarded as data or left unanswered (pveproxy drops the session); why_new=the pump's ping/pong branches had no test; seam=none (ws_send_frame observed via mock); no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (True, 9, b"keepalive"),
            (True, 10, b"pong-body"),
            EOFError,
        ]
        tcp = mock.Mock()
        send = mock.Mock()
        with mock.patch.object(pc, "ws_send_frame", send):
            tcp, _ = self._run_bridge(
                tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: len(send.call_args_list) >= 2))
        data_calls = [(c.args[1], c.args[2]) for c in send.call_args_list]
        self.assertIn((b"keepalive", 0xA), data_calls)
        self.assertEqual([op for _, op in data_calls].count(0xA), 1)
        tcp.sendall.assert_not_called()

    def test_viewer_input_relayed_to_server(self):
        # Value: protects=viewer input events cross the bridge as masked binary frames to PVE; fails_when=the tcp_to_ws direction is dead and the console renders but accepts no input (the bug this tool exists to fix); why_new=the rewritten input pump had no test; seam=none (ws_send_frame observed via mock); no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        tcp = mock.Mock()
        send = mock.Mock()
        with mock.patch.object(pc, "ws_send_frame", send):
            tcp, _ = self._run_bridge(
                tcp, lambda: (tcp, ("127.0.0.1", 1)), reader,
                recv=[b"key", b"mouse", b""])
        self.assertTrue(self._settle(lambda: len(send.call_args_list) == 3))
        data_calls = [(c.args[1], c.args[2]) for c in send.call_args_list]
        self.assertEqual(data_calls, [(b"key", 2), (b"mouse", 2), (b"", 8)])

    def test_viewer_eof_sends_close_frame_to_server(self):
        # Value: protects=viewer disconnect sends the websocket close frame so PVE tears the vncproxy down instead of leaking it; fails_when=the finally close frame is dropped; why_new=the session-end-from-viewer path had no test; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        tcp = mock.Mock()
        send = mock.Mock()
        with mock.patch.object(pc, "ws_send_frame", send):
            tcp, _ = self._run_bridge(
                tcp, lambda: (tcp, ("127.0.0.1", 1)), reader, recv=[b""])
        self.assertTrue(self._settle(lambda: len(send.call_args_list) == 1))
        self.assertEqual(
            (send.call_args_list[0].args[1], send.call_args_list[0].args[2]),
            (b"", 8))
        tcp.sendall.assert_not_called()

    def test_protocol_error_names_the_violation_on_stderr(self):
        # Value: protects=a parser-level violation surfaces as the one-line protocol-error diagnostic instead of a silently dead viewer socket; fails_when=the ValueError print is dropped; why_new=mocked-reader tests assert shutdown but never the diagnosability promise; seam=none (real WsReader over a fake socket, RSV frame); no_claim=none beyond protects
        class RsvSock:
            def __init__(self):
                self.data = bytes([0xC2, 0x02]) + b"ab"  # RSV1 set, binary

            def recv(self, n):
                out, self.data = self.data[:n], self.data[n:]
                return out

        tcp = mock.Mock()
        tcp.recv.side_effect = OSError("stop")
        err = io.StringIO()
        send = mock.Mock()
        with mock.patch.object(pc, "ws_connect", return_value=(mock.Mock(), b"")), \
                mock.patch.object(pc, "WsReader",
                                  return_value=pc.WsReader(RsvSock())), \
                mock.patch.object(pc.socket, "socket",
                                  return_value=self._listener(
                                      lambda: (tcp, ("127.0.0.1", 1)))), \
                mock.patch.object(pc.subprocess, "Popen",
                                  return_value=mock.Mock(wait=lambda *_: 0)), \
                mock.patch("builtins.open", mock.mock_open()), \
                mock.patch.object(pc, "ws_send_frame", send), \
                mock.patch("sys.stderr", err):
            args = mock.Mock(host="h", node="n", vmid=101, viewer=None,
                             validate_cert=True)
            pc.bridge_and_launch({"port": "5900",
                                  "ticket": "PW:PVEVNC:rest"}, "cookie", args)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        self.assertIn("protocol error", err.getvalue())
        self.assertIn("RSV", err.getvalue())
        tcp.sendall.assert_not_called()

    def test_interleaved_data_frame_during_reassembly_rejected(self):
        # Regression: pre-landing review — a complete data frame interleaved
        # into a fragmented message was forwarded before the reassembled one,
        # reordering server bytes on an RFB stream.
        # Found by /ship red-team review on 2026-11-13
        # Report: .gstack/qa-reports/run-20261113T205424Z
        # Value: protects=RFC 6455 5.4's no-interleaving rule is enforced for complete data frames too; fails_when=fin=1 data frames fall through mid-reassembly and reorder the stream; why_new=only the new-fragment case was rejected; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = [
            (False, 2, b"A"),
            (True, 2, b"B"),
            EOFError,
        ]
        tcp = mock.Mock()
        tcp, _ = self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader)
        self.assertTrue(self._settle(lambda: tcp.shutdown.call_args_list))
        tcp.sendall.assert_not_called()

    def test_econnaborted_storm_detects_dead_viewer(self):
        # Regression: pre-landing review — the ECONNABORTED branch never
        # polled the viewer, so a dead viewer spun the loop forever.
        # Found by /ship red-team review on 2026-11-13
        # Report: .gstack/qa-reports/run-20261113T205424Z
        # Value: protects=the abort-retry path keeps checking viewer liveness; fails_when=viewer.poll() runs only in the timeout branch and a dead viewer pins the session; why_new=the retry loop was added without its own liveness check; seam=none; no_claim=none beyond protects
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        viewer = mock.Mock()
        viewer.poll.return_value = 0  # viewer already dead

        def accept():
            raise OSError(errno.ECONNABORTED, "connection aborted")

        with mock.patch.object(pc.time, "sleep"), \
                self.assertRaises(RuntimeError) as ctx:
            self._run_bridge(mock.Mock(), accept, reader, viewer=viewer)
        self.assertIn("without connecting", str(ctx.exception))

    def test_systemexit_during_wait_terminates_viewer(self):
        # Regression: pre-landing review — pve_console's own signal path (a
        # SystemExit from viewer.wait) had no test proving the viewer is
        # terminated and teardown runs.
        # Found by /ship specialist review on 2026-11-13
        # Report: .gstack/qa-reports/run-20261113T205424Z
        # Value: protects=SIGTERM/SIGINT during the session terminates the viewer and tears the bridge down; fails_when=SystemExit skips the except BaseException path; why_new=the wrapper got this test but the launcher did not; seam=none; no_claim=no real signal delivery
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        tcp = mock.Mock()
        viewer = mock.Mock()
        viewer.wait.side_effect = SystemExit(143)
        with self.assertRaises(SystemExit):
            self._run_bridge(tcp, lambda: (tcp, ("127.0.0.1", 1)), reader,
                             viewer=viewer)
        viewer.terminate.assert_called_once_with()
        tcp.shutdown.assert_called()
        # The finally must arm the teardown guard that ignores repeat signals.
        self.assertTrue(pc._SHUTDOWN_STATE["tearing_down"])

    def test_viewer_death_during_accept_raises(self):
        reader = mock.Mock()
        reader.frame.side_effect = EOFError
        viewer = mock.Mock()
        viewer.poll.return_value = 0  # viewer already dead

        def accept():
            raise socket.timeout()

        with self.assertRaises(RuntimeError) as ctx:
            self._run_bridge(mock.Mock(), accept, reader, viewer=viewer)
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

    def _connect(self, validate_cert, err):
        raw = mock.Mock()
        ctx = mock.Mock()
        ctx.wrap_socket.return_value = raw
        key = base64.b64encode(b"\x01" * 16).decode()
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            f"Sec-WebSocket-Accept: {pc.expected_ws_accept(key)}\r\n\r\n"
        ).encode()
        raw.recv.side_effect = [response]
        with mock.patch.object(pc.socket, "create_connection", return_value=raw), \
                mock.patch.object(pc.ssl, "create_default_context", return_value=ctx), \
                mock.patch.object(pc.os, "urandom", return_value=b"\x01" * 16), \
                mock.patch("sys.stderr", err):
            return pc.ws_connect("h", 8006, "n", 1,
                                 {"port": "5900", "ticket": "T"},
                                 "cookie", validate_cert), ctx

    def test_insecure_mode_warns_cookie_rides_unvalidated(self):
        # Value: protects=--insecure prints the one-line warning naming the root cookie risk; fails_when=the warning is dropped and unvalidated use is silent; why_new=the warning text changed with the default flip and no test read it; seam=none; no_claim=no real TLS handshake
        err = io.StringIO()
        sock, _ = self._connect(False, err)
        self.assertIsNotNone(sock)
        self.assertIn("root session cookie", err.getvalue())
        self.assertIn("--insecure", err.getvalue())

    def test_validate_cert_pins_strict_tls_context(self):
        # Value: protects=the default path demands a valid, hostname-matched certificate; fails_when=CERT_REQUIRED or check_hostname is dropped and the root cookie becomes MITM-readable by default; why_new=the strict branch had no test (only the insecure branch ran); seam=none; no_claim=no real TLS handshake
        err = io.StringIO()
        _, ctx = self._connect(True, err)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIs(ctx.check_hostname, True)
        self.assertEqual(err.getvalue(), "")

    # Regression: pre-landing review — cert failures and other handshake
    # failures must not share one message that coaches users into --insecure.
    # Found by /ship red-team review on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=only certificate failures suggest --insecure; a downgrade or cipher failure gets a neutral message; fails_when=any SSLError recommends disabling validation (an active MITM could be the cause); why_new=the translation branch had zero coverage and conflated both classes; seam=none; no_claim=no real TLS handshake
    def test_cert_failure_suggests_insecure(self):
        raw, ctx = mock.Mock(), mock.Mock()
        ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        with mock.patch.object(pc.socket, "create_connection", return_value=raw), \
                mock.patch.object(pc.ssl, "create_default_context", return_value=ctx), \
                self.assertRaises(RuntimeError) as caught:
            pc.ws_connect("h", 8006, "n", 1, {"port": "5900", "ticket": "T"},
                          "cookie", validate_cert=True)
        self.assertIn("--insecure", str(caught.exception))
        self.assertNotIsInstance(caught.exception, ssl.SSLError)

    def test_other_tls_failure_does_not_suggest_insecure(self):
        raw, ctx = mock.Mock(), mock.Mock()
        ctx.wrap_socket.side_effect = ssl.SSLError(
            1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")
        with mock.patch.object(pc.socket, "create_connection", return_value=raw), \
                mock.patch.object(pc.ssl, "create_default_context", return_value=ctx), \
                self.assertRaises(RuntimeError) as caught:
            pc.ws_connect("h", 8006, "n", 1, {"port": "5900", "ticket": "T"},
                          "cookie", validate_cert=True)
        self.assertNotIn("--insecure", str(caught.exception))
        self.assertIn("TLS handshake", str(caught.exception))


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

    # Regression: coverage audit flagged malformed pvesh JSON escaping as a
    # JSONDecodeError traceback instead of the one-line error contract.
    # Found by /ship coverage audit on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=a non-JSON pvesh body (ticket line present) surfaces as a one-line RuntimeError without echoing the body; fails_when=json.loads raises through mint; why_new=the traceback can leak the ticket-bearing body on the failure path; seam=none; no_claim=none beyond protects
    def test_malformed_json_translates_to_runtime_error(self):
        with mock.patch.object(pc.subprocess, "check_output",
                               return_value=b'{"ticket":"SECRETONE"\nPVE:apiticket'), \
                self.assertRaises(RuntimeError) as ctx:
            pc.mint("h", "n", "1")
        self.assertIn("non-JSON", str(ctx.exception))
        self.assertNotIn("SECRETONE", str(ctx.exception))

    # Regression: pre-landing review — a valid-JSON non-object pvesh body
    # raised AttributeError past the one-line error contract.
    # Found by /ship specialist review on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=a non-object JSON body surfaces as a one-line RuntimeError; fails_when=vnc.get is called on a list/scalar; why_new=MintTests only covered dict bodies; seam=none; no_claim=none beyond protects
    def test_non_dict_json_translates_to_runtime_error(self):
        for body in (b'[1,2]\nPVE:apiticket', b'"ok"\nPVE:apiticket',
                     b'null\nPVE:apiticket'):
            with mock.patch.object(pc.subprocess, "check_output",
                                   return_value=body), \
                    self.assertRaises(RuntimeError) as ctx:
                pc.mint("h", "n", "1")
            self.assertIn("unexpected JSON", str(ctx.exception))
            self.assertNotIn("apiticket", str(ctx.exception))

    # Regression: pre-landing review — non-UTF-8 ssh output raised
    # UnicodeDecodeError past the one-line error contract.
    # Found by /ship red-team review on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=undecodable ssh output surfaces as a one-line RuntimeError; fails_when=UnicodeDecodeError escapes mint; why_new=every other mint failure mode was covered but this one; seam=none; no_claim=none beyond protects
    def test_non_utf8_output_translates_to_runtime_error(self):
        with mock.patch.object(pc.subprocess, "check_output",
                               return_value=b"\xff\xfe junk\nPVE:apiticket"), \
                self.assertRaises(RuntimeError) as ctx:
            pc.mint("h", "n", "1")
        self.assertIn("non-UTF-8", str(ctx.exception))
        self.assertNotIn("apiticket", str(ctx.exception))


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

    def test_insecure_flag_skips_cert_validation(self):
        # Value: protects=--insecure reaches the websocket as validate_cert=False; fails_when=the flag wiring drops and self-signed hosts cannot connect at all; why_new=the PR's headline flag had no wiring test; seam=none (mint/bridge_and_launch mocked); no_claim=none beyond protects
        br = mock.Mock(return_value=0)
        with mock.patch.object(pc, "mint",
                               return_value=({"port": "5900", "ticket": "T"},
                                             "PVE:cookie")), \
                mock.patch.object(pc, "bridge_and_launch", br), \
                mock.patch.object(pc.signal, "signal"):
            rc = pc.main(["--host", "h", "--node", "n", "--vmid", "1",
                          "--insecure"])
        self.assertEqual(rc, 0)
        self.assertIs(br.call_args.args[2].validate_cert, False)

    def test_default_validates_certificate(self):
        # Value: protects=the secure default reaches the websocket as validate_cert=True when no flags are given; fails_when=the default flips to insecure and the root cookie rides unvalidated connections; why_new=the PR's security default flip had no wiring test; seam=none; no_claim=none beyond protects
        br = mock.Mock(return_value=0)
        with mock.patch.object(pc, "mint",
                               return_value=({"port": "5900", "ticket": "T"},
                                             "PVE:cookie")), \
                mock.patch.object(pc, "bridge_and_launch", br), \
                mock.patch.object(pc.signal, "signal"):
            rc = pc.main(["--host", "h", "--node", "n", "--vmid", "1"])
        self.assertEqual(rc, 0)
        self.assertIs(br.call_args.args[2].validate_cert, True)

    # Regression: coverage audit flagged socket/TLS failures bypassing the
    # one-line error contract (ConnectionRefusedError is an OSError, not a
    # RuntimeError).
    # Found by /ship coverage audit on 2026-11-13
    # Report: .gstack/qa-reports/run-20261113T205424Z
    # Value: protects=connection-level failures surface as a one-line error with exit 2; fails_when=OSError escapes main; why_new=a refused host is the most common real-world failure and previously printed a traceback; seam=none; no_claim=none beyond protects
    def test_connection_failure_prints_one_line_and_exits_2(self):
        with mock.patch.object(pc, "mint",
                               side_effect=ConnectionRefusedError("refused")), \
                mock.patch.object(pc.signal, "signal"), \
                mock.patch("sys.stderr", new=io.StringIO()) as err:
            rc = pc.main(["--host", "h", "--node", "n", "--vmid", "1"])
        self.assertEqual(rc, 2)
        self.assertEqual(err.getvalue(), "error: refused\n")

    def test_node_charset_boundaries(self):
        # Regression: pre-landing review — --node was interpolated raw into
        # the HTTP request line; CRLF could smuggle headers into the upgrade.
        # Found by /ship security specialist on 2026-11-13
        # Report: .gstack/qa-reports/run-20261113T205424Z
        # Value: protects=the node name is DNS-label shaped before it reaches ssh or the request line; fails_when=CRLF, shell metacharacters, empty, unicode, or over-long names pass through; why_new=mint shlex.quoted the ssh path but the request line stayed unvalidated; seam=none; no_claim=none beyond protects
        for node in ("pve", "a" * 63):  # accepted shapes
            with mock.patch.object(pc, "mint",
                                   side_effect=ValueError("stop-here")), \
                    mock.patch.object(pc.signal, "signal"), \
                    self.assertRaises(ValueError):
                pc.main(["--host", "h", "--node", node, "--vmid", "1"])
        for node in ("", ".pve", "-pve", "a" * 64, "nøde", "a b",
                     "a\r\nX-Evil: 1"):
            with self.assertRaises(SystemExit):
                pc.main(["--host", "h", "--node", node, "--vmid", "1"])

    def test_signal_during_teardown_is_ignored(self):
        # Regression: pre-landing review — a second signal while the teardown
        # finally ran raised SystemExit from the handler and abandoned the
        # cleanup tail (the .vv unlink).
        # Found by /ship red-team review on 2026-11-13
        # Report: .gstack/qa-reports/run-20261113T205424Z
        # Value: protects=repeat TERM/Ctrl-C cannot abort the .vv cleanup halfway; fails_when=the handler raises unconditionally during teardown; why_new=the ticket-bearing .vv could survive on disk; seam=none; no_claim=no real signal delivery
        with self.assertRaises(SystemExit) as first:
            pc._on_signal(15, None)
        self.assertEqual(first.exception.code, 143)
        old = pc._SHUTDOWN_STATE["tearing_down"]
        pc._SHUTDOWN_STATE["tearing_down"] = True
        try:
            pc._on_signal(15, None)  # must not raise
        finally:
            pc._SHUTDOWN_STATE["tearing_down"] = old


if __name__ == "__main__":
    unittest.main()
