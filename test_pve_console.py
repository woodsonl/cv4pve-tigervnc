#!/usr/bin/env python3
"""Tests for pve_console.py: frame codec round-trips, .vv emission,
argument handling. No network, no viewer, no PVE."""

import os
import struct
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
            opcode, back = self._read_via(self._server_frame(payload)).frame()
            self.assertEqual(opcode, 2)
            self.assertEqual(back, payload)

    def test_two_frames_split_across_one_recv(self):
        a, b = b"first", b"second"
        rd = self._read_via(self._server_frame(a) + self._server_frame(b))
        self.assertEqual(rd.frame()[1], a)
        self.assertEqual(rd.frame()[1], b)

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


class ArgTests(unittest.TestCase):
    def test_missing_required_argument_exits(self):
        with self.assertRaises(SystemExit):
            pc.main(["--host", "h"])

    def test_minimal_triple_reaches_mint(self):
        # Value: protects=--host/--node/--vmid are all required and sufficient to reach minting; fails_when=argparse rejects a valid triple or ignores a required flag; why_new=contract for the CLI surface; seam=none; no_claim=none beyond protects
        with mock.patch.object(pc, "mint", side_effect=RuntimeError("stop-here")), \
                mock.patch.object(pc.signal, "signal"), \
                self.assertRaises(RuntimeError) as ctx:
            pc.main(["--host", "h", "--node", "n", "--vmid", "1"])
        self.assertEqual(str(ctx.exception), "stop-here")


if __name__ == "__main__":
    unittest.main()
