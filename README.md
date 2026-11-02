# cv4pve-tigervnc

cv4pve-vdi launches whatever you put in its Viewer path and hands it one
argument: the path to a `.vv` file it just wrote for `remote-viewer`.
`remote-viewer` has no maintained macOS build, so this script stands in as the
viewer. It reads the `.vv`, throws it away, and starts TigerVNC against
cv4pve-vdi's local WebSocket bridge.

cv4pve-vdi is a [Corsinvest](https://github.com/Corsinvest/cv4pve-vdi) app for
opening Proxmox VE consoles. This repo holds only the macOS viewer shim. It is
not affiliated with Corsinvest or Proxmox.

## Requirements

- [TigerVNC](https://www.tigervnc.org/) for macOS. Verified against 1.16.2.
- cv4pve-vdi 1.8.0, the release whose `.vv` writer this matches.
- Python 3. Stdlib only, nothing to install. Verified on the macOS system
  Python 3.9.6.

## Setup

```sh
chmod +x cv4pve_tigervnc_wrapper.py
```

Then in cv4pve-vdi, under Settings → Launchers:

1. Set Viewer path to the absolute path of `cv4pve_tigervnc_wrapper.py`.
2. Under Protocols, turn SPICE off and leave VNC on. TigerVNC speaks VNC, and
   the wrapper rejects a SPICE `.vv` rather than pretending otherwise.
3. Leave TLS certificate validation on. Nothing here needs it off.

If TigerVNC is somewhere other than `/Applications`, point
`CV4PVE_TIGERVNC_VIEWER` at the binary. cv4pve-vdi passes its own environment
down, so export it before launching cv4pve-vdi, or set it in a
`LaunchServices`-visible way.

## What the wrapper does

cv4pve-vdi writes this, from `RemoteViewerHelper.CreateVncWebSocketBridgeAsync`:

```ini
[virt-viewer]
type=vnc
host=127.0.0.1
port=49312
password=<8 random chars>:PVEVNC:<hex ts>:<user>:<path>:<port>::<RSA signature>
title=VNC: VM 100
delete-this-file=1
```

The bridge listens on an ephemeral local port, not a `59xx` display port.

The `password=` value is the whole ticket, and PVE builds it in two pieces.
`PVE::API2::Nodes.pm` generates an 8-character VNC password, prepends it to the
RSA ticket, and hands the pair to the API. Only those first 8 bytes are the
VncAuth secret, which is what TigerVNC needs. The steps:

1. Parse the `.vv` and check every field against that exact shape.
2. Delete the `.vv`. This happens right after reading it into memory and before
   validation, so a rejected connection leaves no ticket on disk either.
3. Write the password file: the first 8 ticket bytes through DES with the VNC
   obfuscation key, the same output `vncpasswd` produces. Mode 0600, from
   `mkstemp`.
4. Launch the viewer:

   ```
   vncviewer -passwd <password-file> -SecurityTypes VncAuth 127.0.0.1::49312
   ```

   The double colon matters. TigerVNC reads `host:N` as display `N` and adds
   5900, and reads `host::N` as literal port `N`
   (`common/network/TcpSocket.cxx`, `getHostAndPort`). The bridge port is
   ephemeral, so it has to be the port form.
5. Wait for the viewer, then delete the password file.

The wrapper has to stay alive for the whole session. cv4pve-vdi's
`RemoteViewerService` disposes the bridge when the process it launched exits,
so a wrapper that exits after spawning the viewer would take the console down
with it. `SIGTERM` is turned into a `SystemExit` so the password file gets
removed on that path too.

## Errors

Every failure prints one line starting with `error:` and exits 2, before
anything is launched. The three ticket messages tell you which stage broke:

| Message | Meaning |
| --- | --- |
| `missing key(s) in connection file: ...` | cv4pve-vdi wrote a file it shouldn't have. It names the keys it did find. |
| `password= is empty: cv4pve-vdi got no VNC ticket from PVE` | PVE refused the ticket. Check that the user holds VM.Console and VM.Audit on the guest, and that the guest is running. |
| `password (VNC ticket) has N unexpected character(s): U+XXXX` | Something other than PVE wrote this file, or the ticket was mangled. Reports the offending code points. |

The rest fail closed on the file itself: unknown or duplicate keys, a second
section, a `[DEFAULT]` section, `type` other than `vnc`, `host` other than
`127.0.0.1`, a port outside 1-65535, and a `.vv` over 4096 bytes.

## Why it checks so much of the file

The `.vv` is written from a Proxmox API response, and this script feeds it to a
viewer. So:

- The viewer starts from a list argv. No shell, no `eval`, no `shell=True`, so
  nothing in the file can become command syntax. Printable ASCII `!` through
  `~` is allowed in the ticket on purpose, including characters a shell would
  read. The ticket reaches one place, the 0600 password file, and `configparser`
  with `interpolation=None` round-trips every one of them unchanged.
- The ticket never enters argv, the environment, or any log. The password file
  holds the 8 obfuscated bytes and nothing else.
- `VNC_PASSWORD` and `VNC_USERNAME` are stripped from the child environment.
  TigerVNC prefers those over `-passwd`, so a stale value would silently beat
  the ticket.
- Every check runs before the viewer launches. A file that fails anything gets
  deleted and nothing starts.

## Tests

```sh
python3 -m unittest test_cv4pve_tigervnc_wrapper
```

35 tests, no network, and TigerVNC is never started. `find_viewer` is patched
out except in one test that runs `main()` against a `/bin/sh` stub which records
its argv and exits 7, checking that the wrapper waits for the child, passes the
exit code up, and leaves no password file behind.

The DES port is checked against the vector documented in TigerVNC's `d3des.c`
(`c95744256a5ed31d`) and cross-checked against `openssl enc -des-ecb`, which the
test skips if this machine's OpenSSL has no DES. TigerVNC's DES consumes each key
byte least-significant-bit-first and ignores the high bit, so a textbook-DES
oracle disagrees with it. The equivalence
`des_vnc(block, key) == std_des(block, bitrev_each_byte(key))` is asserted both
ways.

## Provenance

The DES tables and round function are transcribed from TigerVNC's
`common/rfb/d3des.c`. That file is Richard Outerbridge's D3DES V5.09, marked
public domain in its own header, reduced to single-length DES by AT&T
Laboratories Cambridge with the `bytebit[]` table reversed. The AT&T changes
carry a copyright line and a warranty disclaimer, not a copyleft grant, so the
port can sit here under whatever license this repo picks. TigerVNC itself is
GPLv2; nothing from outside `d3des.c` was taken, and the viewer is a separate
process this script only execs.

Everything else was written for this repo. `.vv` field names and the ticket
format come from reading `Corsinvest/cv4pve-api-dotnet`
`RemoteViewerHelper.CreateVncWebSocketBridgeAsync` and `PVE::API2::Nodes.pm` at
the versions named above.
