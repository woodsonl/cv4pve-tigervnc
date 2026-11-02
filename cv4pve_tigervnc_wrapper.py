#!/usr/bin/env python3
"""Launch TigerVNC (vncviewer) for a cv4pve-vdi VNC connection file.

cv4pve-vdi (Corsinvest) execs the configured viewer with one argument: a .vv
file it wrote for remote-viewer (virt-viewer). remote-viewer has no maintained
macOS build, so this wrapper stands in as the viewer:

  1. strictly parse the .vv file (only the exact VNC shape cv4pve-vdi emits is
     accepted; SPICE files and anything else are rejected),
  2. delete the .vv file immediately after parsing,
  3. write the one-time VNC ticket as a vncpasswd-format password file
     (0600, DES-obfuscated exactly like `vncpasswd`),
  4. launch TigerVNC against the localhost bridge on 127.0.0.1::<port> and
     stay alive until the viewer exits — cv4pve-vdi tears down its websocket
     bridge when the process it launched exits, so the wrapper must outlive
     the viewer,
  5. delete the password file when the viewer exits (also on SIGTERM/SIGINT).

Security properties:
  - Python stdlib only; the viewer is launched with a list argv, no shell
    anywhere, so no component of the .vv can become command syntax.
  - The ticket never appears in argv, env, or logs. It exists only inside the
    obfuscated password file, which holds just the first 8 ticket bytes (the
    entire VncAuth key space) plus nothing else.
  - VNC_PASSWORD/VNC_USERNAME are stripped from the viewer environment: the
    TigerVNC viewer prefers those env vars over -passwd, and a stale value
    would silently override the ticket.
  - Fail closed: unknown keys/sections, missing keys, duplicate keys, a host
    other than 127.0.0.1, a non-numeric port, and tickets outside the PVE
    ticket charset are all rejected before anything is launched.

Setup:
  chmod +x cv4pve_tigervnc_wrapper.py
  cv4pve-vdi -> Settings -> Launchers -> Viewer path: <this file>
  Settings -> Protocols: disable SPICE (TigerVNC is VNC-only).
  Override the viewer binary with $CV4PVE_TIGERVNC_VIEWER if needed.
"""

import configparser
import contextlib
import os
import re
import signal
import subprocess
import sys
import tempfile

DEFAULT_VIEWER = "/Applications/TigerVNC.app/Contents/MacOS/vncviewer"
VIEWER_ENV_OVERRIDE = "CV4PVE_TIGERVNC_VIEWER"

# vncpasswd obfuscation: DES-ECB with this fixed key over the first 8 bytes
# of the password (TigerVNC common/rfb/obfuscate.cxx, d3desObfuscationKey).
_OBFUSCATION_KEY = bytes((23, 82, 107, 6, 35, 78, 88, 7))

# What PVE puts in password= for a websocket console (PVE::API2 vncproxy/vncshell):
#   "<pw>:PVEVNC:<hex-ts>:<user>:<path>:<port>::<base64 RSA sig>"
# where <pw> is 8 random bytes from ord('!')..ord('`') (PVE::Ticket::generate_vnc_password)
# and the API documents the whole value as printable ASCII '!'..'~'. So the
# whitelist is exactly that range: printable ASCII, which still excludes every
# space, control, and high-byte character. The RSA signature is standard
# base64 (MIME::Base64: A-Za-z0-9+/=), so no character outside the range appears.
_TICKET_CHAR_RE = re.compile(r"[\x21-\x7e]")
_TICKET_RE = re.compile(r"^[\x21-\x7e]{1,4096}$")
_PORT_RE = re.compile(r"^[0-9]{1,5}$")
_TITLE_RE = re.compile(r"^[ -~]{1,200}$")

_VV_MAX_BYTES = 4096
_REQUIRED_KEYS = ("type", "host", "port", "password")
_KNOWN_KEYS = frozenset(_REQUIRED_KEYS + ("title", "delete-this-file"))


class VvError(Exception):
    """A .vv file did not match the exact VNC shape cv4pve-vdi emits."""


# --------------------------------------------------------------------------
# DES, ported line-by-line from TigerVNC common/rfb/d3des.c. This is NOT
# textbook DES: d3des reverses its bytebit[] table "so that the most
# significant bit in each byte of the key is ignored, not the least" — VNC
# consumes key bytes LSB-first and discards the DES parity bit. Equivalently,
# des_vnc(block, key) == standard_des(block, bit_reverse_each_byte(key)).
# Cross-checks in test_cv4pve_tigervnc_wrapper.py: openssl enc -des-ecb with
# bit-reversed keys, plus d3des.c's own validation vector recomputed through
# the same bit-reversal. Only single-block encryption is needed (vncpasswd
# obfuscation), so DE1 and triple-length support are omitted.
# --------------------------------------------------------------------------

_M32 = 0xFFFFFFFF

# Transcribed mechanically from TigerVNC common/rfb/d3des.c (d3des V5.09 by
# Richard Outerbridge); the implementation is validated in the test suite
# against LibreSSL-ECB and d3des.c's own validation vectors.
_BYTEBIT = (
    1, 2, 4, 8, 16, 32, 64, 128,
)

_BIGBYTE = (
    0x800000, 0x400000, 0x200000, 0x100000, 0x080000, 0x040000,
    0x020000, 0x010000, 0x008000, 0x004000, 0x002000, 0x001000,
    0x000800, 0x000400, 0x000200, 0x000100, 0x000080, 0x000040,
    0x000020, 0x000010, 0x000008, 0x000004, 0x000002, 0x000001,
)

_PC1 = (
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
)

_TOTROT = (
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28,
)

_PC2 = (
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
    22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
)

_SP1 = (
    0x1010400, 0x000000, 0x010000, 0x1010404, 0x1010004, 0x010404,
    0x000004, 0x010000, 0x000400, 0x1010400, 0x1010404, 0x000400,
    0x1000404, 0x1010004, 0x1000000, 0x000004, 0x000404, 0x1000400,
    0x1000400, 0x010400, 0x010400, 0x1010000, 0x1010000, 0x1000404,
    0x010004, 0x1000004, 0x1000004, 0x010004, 0x000000, 0x000404,
    0x010404, 0x1000000, 0x010000, 0x1010404, 0x000004, 0x1010000,
    0x1010400, 0x1000000, 0x1000000, 0x000400, 0x1010004, 0x010000,
    0x010400, 0x1000004, 0x000400, 0x000004, 0x1000404, 0x010404,
    0x1010404, 0x010004, 0x1010000, 0x1000404, 0x1000004, 0x000404,
    0x010404, 0x1010400, 0x000404, 0x1000400, 0x1000400, 0x000000,
    0x010004, 0x010400, 0x000000, 0x1010004,
)

_SP2 = (
    0x80108020, 0x80008000, 0x008000, 0x108020, 0x100000, 0x000020,
    0x80100020, 0x80008020, 0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x100000, 0x000020, 0x80100020, 0x108000, 0x100020,
    0x80008020, 0x000000, 0x80000000, 0x008000, 0x108020, 0x80100000,
    0x100020, 0x80000020, 0x000000, 0x108000, 0x008020, 0x80108000,
    0x80100000, 0x008020, 0x000000, 0x108020, 0x80100020, 0x100000,
    0x80008020, 0x80100000, 0x80108000, 0x008000, 0x80100000, 0x80008000,
    0x000020, 0x80108020, 0x108020, 0x000020, 0x008000, 0x80000000,
    0x008020, 0x80108000, 0x100000, 0x80000020, 0x100020, 0x80008020,
    0x80000020, 0x100020, 0x108000, 0x000000, 0x80008000, 0x008020,
    0x80000000, 0x80100020, 0x80108020, 0x108000,
)

_SP3 = (
    0x000208, 0x8020200, 0x000000, 0x8020008, 0x8000200, 0x000000,
    0x020208, 0x8000200, 0x020008, 0x8000008, 0x8000008, 0x020000,
    0x8020208, 0x020008, 0x8020000, 0x000208, 0x8000000, 0x000008,
    0x8020200, 0x000200, 0x020200, 0x8020000, 0x8020008, 0x020208,
    0x8000208, 0x020200, 0x020000, 0x8000208, 0x000008, 0x8020208,
    0x000200, 0x8000000, 0x8020200, 0x8000000, 0x020008, 0x000208,
    0x020000, 0x8020200, 0x8000200, 0x000000, 0x000200, 0x020008,
    0x8020208, 0x8000200, 0x8000008, 0x000200, 0x000000, 0x8020008,
    0x8000208, 0x020000, 0x8000000, 0x8020208, 0x000008, 0x020208,
    0x020200, 0x8000008, 0x8020000, 0x8000208, 0x000208, 0x8020000,
    0x020208, 0x000008, 0x8020008, 0x020200,
)

_SP4 = (
    0x802001, 0x002081, 0x002081, 0x000080, 0x802080, 0x800081,
    0x800001, 0x002001, 0x000000, 0x802000, 0x802000, 0x802081,
    0x000081, 0x000000, 0x800080, 0x800001, 0x000001, 0x002000,
    0x800000, 0x802001, 0x000080, 0x800000, 0x002001, 0x002080,
    0x800081, 0x000001, 0x002080, 0x800080, 0x002000, 0x802080,
    0x802081, 0x000081, 0x800080, 0x800001, 0x802000, 0x802081,
    0x000081, 0x000000, 0x000000, 0x802000, 0x002080, 0x800080,
    0x800081, 0x000001, 0x802001, 0x002081, 0x002081, 0x000080,
    0x802081, 0x000081, 0x000001, 0x002000, 0x800001, 0x002001,
    0x802080, 0x800081, 0x002001, 0x002080, 0x800000, 0x802001,
    0x000080, 0x800000, 0x002000, 0x802080,
)

_SP5 = (
    0x000100, 0x2080100, 0x2080000, 0x42000100, 0x080000, 0x000100,
    0x40000000, 0x2080000, 0x40080100, 0x080000, 0x2000100, 0x40080100,
    0x42000100, 0x42080000, 0x080100, 0x40000000, 0x2000000, 0x40080000,
    0x40080000, 0x000000, 0x40000100, 0x42080100, 0x42080100, 0x2000100,
    0x42080000, 0x40000100, 0x000000, 0x42000000, 0x2080100, 0x2000000,
    0x42000000, 0x080100, 0x080000, 0x42000100, 0x000100, 0x2000000,
    0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000,
    0x42080000, 0x2080100, 0x40080100, 0x000100, 0x2000000, 0x42080000,
    0x42080100, 0x080100, 0x42000000, 0x42080100, 0x2080000, 0x000000,
    0x40080000, 0x42000000, 0x080100, 0x2000100, 0x40000100, 0x080000,
    0x000000, 0x40080000, 0x2080100, 0x40000100,
)

_SP6 = (
    0x20000010, 0x20400000, 0x004000, 0x20404010, 0x20400000, 0x000010,
    0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010,
    0x400010, 0x20004000, 0x20000000, 0x004010, 0x000000, 0x400010,
    0x20004010, 0x004000, 0x404000, 0x20004010, 0x000010, 0x20400010,
    0x20400010, 0x000000, 0x404010, 0x20404000, 0x004010, 0x404000,
    0x20404000, 0x20000000, 0x20004000, 0x000010, 0x20400010, 0x404000,
    0x20404010, 0x400000, 0x004010, 0x20000010, 0x400000, 0x20004000,
    0x20000000, 0x004010, 0x20000010, 0x20404010, 0x404000, 0x20400000,
    0x404010, 0x20404000, 0x000000, 0x20400010, 0x000010, 0x004000,
    0x20400000, 0x404010, 0x004000, 0x400010, 0x20004010, 0x000000,
    0x20404000, 0x20000000, 0x400010, 0x20004010,
)

_SP7 = (
    0x200000, 0x4200002, 0x4000802, 0x000000, 0x000800, 0x4000802,
    0x200802, 0x4200800, 0x4200802, 0x200000, 0x000000, 0x4000002,
    0x000002, 0x4000000, 0x4200002, 0x000802, 0x4000800, 0x200802,
    0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002,
    0x4200000, 0x000800, 0x000802, 0x4200802, 0x200800, 0x000002,
    0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802,
    0x4000802, 0x4200002, 0x4200002, 0x000002, 0x200002, 0x4000000,
    0x4000800, 0x200000, 0x4200800, 0x000802, 0x200802, 0x4200800,
    0x000802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0x000000,
    0x000002, 0x4200802, 0x000000, 0x200802, 0x4200000, 0x000800,
    0x4000002, 0x4000800, 0x000800, 0x200002,
)

_SP8 = (
    0x10001040, 0x001000, 0x040000, 0x10041040, 0x10000000, 0x10001040,
    0x000040, 0x10000000, 0x040040, 0x10040000, 0x10041040, 0x041000,
    0x10041000, 0x041040, 0x001000, 0x000040, 0x10040000, 0x10000040,
    0x10001000, 0x001040, 0x041000, 0x040040, 0x10040040, 0x10041000,
    0x001040, 0x000000, 0x000000, 0x10040040, 0x10000040, 0x10001000,
    0x041040, 0x040000, 0x041040, 0x040000, 0x10041000, 0x001000,
    0x000040, 0x10040040, 0x001000, 0x041040, 0x10001000, 0x000040,
    0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x040000, 0x10001040,
    0x000000, 0x10041040, 0x040040, 0x10000040, 0x10040000, 0x10001000,
    0x10001040, 0x000000, 0x10041040, 0x041000, 0x041000, 0x001040,
    0x001040, 0x040040, 0x10000000, 0x10041000,
)


def _deskey(key8):
    # d3des.c deskey(): build the 32-word raw key schedule (encrypt mode).
    pc1m = [0] * 56
    pcr = [0] * 56
    kn = [0] * 32
    for j in range(56):
        idx = _PC1[j]
        pc1m[j] = 1 if (key8[idx >> 3] & _BYTEBIT[idx & 7]) else 0
    for i in range(16):
        # This port only encrypts (EN0); decryption rotates (15 - i) << 1.
        m = i << 1
        n = m + 1
        kn[m] = kn[n] = 0
        for j in range(28):
            idx = j + _TOTROT[i]
            pcr[j] = pc1m[idx] if idx < 28 else pc1m[idx - 28]
        for j in range(28, 56):
            idx = j + _TOTROT[i]
            pcr[j] = pc1m[idx] if idx < 56 else pc1m[idx - 28]
        for j in range(24):
            if pcr[_PC2[j]]:
                kn[m] |= _BIGBYTE[j]
            if pcr[_PC2[j + 24]]:
                kn[n] |= _BIGBYTE[j]
    return kn


def _cookey(raw1):
    # d3des.c cookey(): rearrange the raw schedule into the bit alignment the
    # round function indexes.
    dough = [0] * 32
    for i in range(16):
        raw0 = raw1[2 * i]
        rawb = raw1[2 * i + 1]
        dough[2 * i] = (
            ((raw0 & 0x00FC0000) << 6)
            | ((raw0 & 0x00000FC0) << 10)
            | ((rawb & 0x00FC0000) >> 10)
            | ((rawb & 0x00000FC0) >> 6)
        ) & _M32
        dough[2 * i + 1] = (
            ((raw0 & 0x0003F000) << 12)
            | ((raw0 & 0x0000003F) << 16)
            | ((rawb & 0x0003F000) >> 4)
            | (rawb & 0x0000003F)
        ) & _M32
    return dough


def _desfunc(block, keys):
    # d3des.c desfunc(): 16 Feistel rounds with the initial/final permutation
    # folded in as byte shuffling.
    leftt, right = block[0], block[1]
    work = ((leftt >> 4) ^ right) & 0x0F0F0F0F
    right ^= work
    leftt ^= (work << 4) & _M32
    work = ((leftt >> 16) ^ right) & 0x0000FFFF
    right ^= work
    leftt ^= (work << 16) & _M32
    work = ((right >> 2) ^ leftt) & 0x33333333
    leftt ^= work
    right ^= (work << 2) & _M32
    work = ((right >> 8) ^ leftt) & 0x00FF00FF
    leftt ^= work
    right ^= (work << 8) & _M32
    right = ((right << 1) | (right >> 31)) & _M32
    work = (leftt ^ right) & 0xAAAAAAAA
    leftt ^= work
    right ^= work
    leftt = ((leftt << 1) | (leftt >> 31)) & _M32

    k = 0
    for _ in range(8):
        work = (((right << 28) | (right >> 4)) & _M32) ^ keys[k]
        k += 1
        fval = _SP7[work & 0x3F]
        fval |= _SP5[(work >> 8) & 0x3F]
        fval |= _SP3[(work >> 16) & 0x3F]
        fval |= _SP1[(work >> 24) & 0x3F]
        work = right ^ keys[k]
        k += 1
        fval |= _SP8[work & 0x3F]
        fval |= _SP6[(work >> 8) & 0x3F]
        fval |= _SP4[(work >> 16) & 0x3F]
        fval |= _SP2[(work >> 24) & 0x3F]
        leftt ^= fval

        work = (((leftt << 28) | (leftt >> 4)) & _M32) ^ keys[k]
        k += 1
        fval = _SP7[work & 0x3F]
        fval |= _SP5[(work >> 8) & 0x3F]
        fval |= _SP3[(work >> 16) & 0x3F]
        fval |= _SP1[(work >> 24) & 0x3F]
        work = leftt ^ keys[k]
        k += 1
        fval |= _SP8[work & 0x3F]
        fval |= _SP6[(work >> 8) & 0x3F]
        fval |= _SP4[(work >> 16) & 0x3F]
        fval |= _SP2[(work >> 24) & 0x3F]
        right ^= fval

    right = ((right << 31) | (right >> 1)) & _M32
    work = (leftt ^ right) & 0xAAAAAAAA
    leftt ^= work
    right ^= work
    leftt = ((leftt << 31) | (leftt >> 1)) & _M32
    work = ((leftt >> 8) ^ right) & 0x00FF00FF
    right ^= work
    leftt ^= (work << 8) & _M32
    work = ((leftt >> 2) ^ right) & 0x33333333
    right ^= work
    leftt ^= (work << 2) & _M32
    work = ((right >> 16) ^ leftt) & 0x0000FFFF
    leftt ^= work
    right ^= (work << 16) & _M32
    work = ((right >> 4) ^ leftt) & 0x0F0F0F0F
    leftt ^= work
    right ^= (work << 4) & _M32
    # d3des swaps the halves on the way out (block[0]=right, block[1]=leftt).
    return right, leftt


_SCHEDULE_CACHE = {}


def _fixed_schedule():
    if "sched" not in _SCHEDULE_CACHE:
        _SCHEDULE_CACHE["sched"] = _cookey(_deskey(_OBFUSCATION_KEY))
    return _SCHEDULE_CACHE["sched"]


def des_block(block8, key8):
    """DES-encrypt one 8-byte block with an 8-byte key; returns 8 bytes."""
    words = (
        ((block8[0] << 24) | (block8[1] << 16) | (block8[2] << 8) | block8[3]),
        ((block8[4] << 24) | (block8[5] << 16) | (block8[6] << 8) | block8[7]),
    )
    right, leftt = _desfunc(words, _cookey(_deskey(key8)))
    return bytes(
        (
            right >> 24 & 0xFF,
            right >> 16 & 0xFF,
            right >> 8 & 0xFF,
            right & 0xFF,
            leftt >> 24 & 0xFF,
            leftt >> 16 & 0xFF,
            leftt >> 8 & 0xFF,
            leftt & 0xFF,
        )
    )


def vncpasswd_obfuscate(password):
    """Return the 8-byte obfuscated form `vncpasswd`/TigerVNC -passwd expect.

    d3des.c obfuscate(): the first 8 bytes of the string, zero-padded, DES
    encrypted with the fixed VNC key. The result is what CConn::getUserPasswd
    deobfuscates when reading a -passwd file.
    """
    raw = password.encode("utf-8")[:8].ljust(8, b"\x00")
    return des_block(raw, _OBFUSCATION_KEY)


# --------------------------------------------------------------------------
# .vv parsing
# --------------------------------------------------------------------------


def parse_vv(path):
    """Parse a cv4pve-vdi VNC .vv file; return (port, password).

    Accepts only the exact shape RemoteViewerHelper.CreateVncWebSocketBridgeAsync
    writes: one [virt-viewer] section with type=vnc, host=127.0.0.1, a numeric
    port, a charset-whitelisted password (the one-time PVE VNC ticket), and
    the optional title/delete-this-file keys. Anything else fails closed.
    """
    if not os.path.isfile(path):
        raise VvError(f"connection file not found: {path}")
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_VV_MAX_BYTES + 1)
    except OSError as exc:
        raise VvError(f"cannot read connection file: {exc}") from None

    # The .vv holds the one-time ticket in plain text: delete it now, before
    # any validation, so even a rejected connection leaves nothing on disk.
    # All further checks operate on the in-memory copy.
    with contextlib.suppress(OSError):
        os.unlink(path)

    if len(raw) > _VV_MAX_BYTES:
        raise VvError("connection file is implausibly large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise VvError("connection file is not valid UTF-8") from None

    cp = configparser.ConfigParser(interpolation=None, strict=True)
    cp.optionxform = str  # keys are matched case-sensitively, as written
    try:
        cp.read_string(text)
    except configparser.Error as exc:
        raise VvError(f"connection file is not valid INI: {exc}") from None

    if cp.defaults():
        raise VvError("unexpected [DEFAULT] section in connection file")

    sections = cp.sections()
    if sections != ["virt-viewer"]:
        raise VvError(f"expected exactly one [virt-viewer] section, got {sections!r}")

    keys = cp.options("virt-viewer")
    unknown = [k for k in keys if k not in _KNOWN_KEYS]
    if unknown:
        raise VvError(f"unknown key(s) in connection file: {', '.join(sorted(unknown))}")
    missing = [k for k in _REQUIRED_KEYS if k not in keys]
    if missing:
        raise VvError(f"missing key(s) in connection file: {', '.join(missing)}")

    def get(k):
        return cp.get("virt-viewer", k)

    if get("type") != "vnc":
        raise VvError(f"only VNC connection files are supported (type={get('type')!r})")
    if get("host") != "127.0.0.1":
        raise VvError(f"refusing non-localhost VNC target (host={get('host')!r})")

    port = get("port")
    if not _PORT_RE.match(port) or not 1 <= int(port) <= 65535:
        raise VvError(f"invalid port {port!r}")

    password = get("password")
    if not password:
        raise VvError(
            "password= is empty: cv4pve-vdi got no VNC ticket from PVE. Check "
            "that the PVE user holds VM.Console (plus VM.Audit) on this guest, "
            "and that the guest is running"
        )
    if not _TICKET_RE.match(password):
        bad = sorted({ord(c) for c in password if not _TICKET_CHAR_RE.match(c)})
        shown = " ".join(f"U+{c:04X}" for c in bad[:12])
        raise VvError(
            f"password (VNC ticket) has {len(bad)} unexpected character(s): {shown}"
        )

    if "title" in keys and not _TITLE_RE.match(get("title")):
        raise VvError("title failed charset validation")

    if "delete-this-file" in keys and get("delete-this-file") != "1":
        raise VvError(f"unexpected delete-this-file={get('delete-this-file')!r}")

    return int(port), password


# --------------------------------------------------------------------------
# viewer launch
# --------------------------------------------------------------------------


def find_viewer():
    viewer = os.environ.get(VIEWER_ENV_OVERRIDE) or DEFAULT_VIEWER
    if not os.path.isfile(viewer) or not os.access(viewer, os.X_OK):
        raise VvError(
            f"TigerVNC viewer not found or not executable: {viewer} "
            f"(install TigerVNC, or set {VIEWER_ENV_OVERRIDE})"
        )
    return viewer


def build_viewer_argv(viewer, passwd_file, port):
    # -SecurityTypes VncAuth matches what the PVE bridge offers; the host is
    # the constant localhost shape (host=127.0.0.1 is enforced at parse time).
    return [viewer, "-passwd", passwd_file, "-SecurityTypes", "VncAuth", f"127.0.0.1::{port}"]


def child_env():
    # The viewer checks VNC_PASSWORD/VNC_USERNAME before -passwd; a stale
    # value must not override the ticket.
    env = dict(os.environ)
    env.pop("VNC_PASSWORD", None)
    env.pop("VNC_USERNAME", None)
    return env


def main(argv):
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        prog = os.path.basename(sys.argv[0]) or "cv4pve_tigervnc_wrapper.py"
        sys.stderr.write(f"usage: {prog} <connection.vv>\n")
        return 2

    vv_path = argv[0]
    try:
        port, password = parse_vv(vv_path)
    except (VvError, OSError) as exc:
        # The .vv holds the one-time ticket even when malformed; best-effort
        # delete it so a rejected connection leaves nothing behind.
        with contextlib.suppress(OSError):
            os.unlink(vv_path)
        sys.stderr.write(f"error: {exc}\n")
        return 2

    # Replicate delete-this-file=1: the .vv holds the ticket in plain text and
    # is of no further use once parsed. Nothing launched later can read it.
    with contextlib.suppress(OSError):
        os.unlink(vv_path)

    try:
        viewer = find_viewer()
    except VvError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    fd, passwd_file = tempfile.mkstemp(prefix=".pve-vnc-passwd-", suffix=".bin")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, vncpasswd_obfuscate(password))
        os.close(fd)
        proc = subprocess.Popen(
            build_viewer_argv(viewer, passwd_file, port),
            env=child_env(),
        )
        # Outlive the viewer: cv4pve-vdi disposes its websocket bridge when
        # this process exits.
        return proc.wait()
    except OSError as exc:
        sys.stderr.write(f"error: failed to launch viewer: {exc}\n")
        return 2
    finally:
        with contextlib.suppress(OSError):
            os.unlink(passwd_file)


def _install_sigterm_handler():
    # Default SIGTERM kills without running finally blocks; turn it into an
    # exception so the password file cleanup still runs.
    def handler(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, handler)


if __name__ == "__main__":
    _install_sigterm_handler()
    sys.exit(main(sys.argv[1:]))
