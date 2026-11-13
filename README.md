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

There is also a standalone launcher, `pve_console.py`, that opens a console
without cv4pve-vdi at all:

```sh
./pve_console.py --host pve.lan --node pve --vmid 101
```

It mints the one-time ticket over SSH (root key access to the host), bridges
the websocket itself, and runs the wrapper. It exists because cv4pve-vdi's
bridge stops relaying viewer input while the screen keeps updating, so its
consoles can render but accept no input; the standalone launcher relays both
directions until the viewer exits, and closes the viewer's socket the moment
the session ends so no window is left painting a dead console. TLS certificate
validation is on by default; pass `--insecure` for a self-signed host (the
root session cookie then rides an unvalidated connection).


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

One gap no process can close: a `SIGKILL` between launch and exit skips the
cleanup and leaves the 8 obfuscated bytes on disk. They are mode 0600, and the
ticket they encode is one-time and already spent, so the file is worth nothing
once the session is over. `kill -TERM` and normal exit are both covered.

The wrapper has to stay alive for the whole session. cv4pve-vdi's
`RemoteViewerService` disposes the bridge when the process it launched exits,
so a wrapper that exits after spawning the viewer would take the console down
with it. `SIGTERM` and `SIGINT` are turned into a `SystemExit` of 128+N so the
password file gets removed on that path too. The wrapper does not kill the
viewer on those signals: the viewer dies on its own a moment later when
cv4pve-vdi disposes the bridge, which is the designed teardown.

Two more behaviors worth knowing: the wrapper deletes whatever file path it is
given before validating it (cv4pve-vdi hands it a temp file it just wrote; do
not point the script at a file you want to keep), and a viewer that dies of a
signal exits the wrapper with 128+N rather than the viewer's raw negative
status.

## If the picture freezes

A frozen frame means the session is dead, not busy. TigerVNC connects with
exclusive access unless told otherwise, and QEMU (PVE's default
`share=allow-exclusive`) honors that by disconnecting every other viewer: a
new console window ends any live session for the same VM, and the window left
on screen is the dead one. The wrapper passes `-Shared` on every launch, so
its connections disconnect nobody. A client that connects outside the wrapper
and asks for exclusive access can still end a session; `qm monitor <vmid>` →
`info vnc` on the host shows who is connected.

Two host-side lifetimes are worth knowing. The console ticket's roughly
40-second window constrains opening a connection, not a session already
running. An open session ends when the proxy task hits its idle timeout,
about 15 minutes with no traffic in either direction, or when an exclusive
client connects. When that happens, cv4pve-vdi's bridge does not always tell
the viewer — it can leave the local socket open, so TigerVNC keeps the last
framebuffer and your input goes nowhere. Close the window and open the
console again.

## Errors

Every rejection prints one line starting with `error:` and exits 2, before
anything is launched; a bad invocation (no argument, or `-h`) prints a `usage:`
line instead. Diagnostics name the failed check, not the bytes that failed
it. Two deliberate exceptions, both bounded: the charset failure reports the
Unicode code points of rejected characters (never the characters), and the
unknown-key message echoes key names only when they look like something
cv4pve-vdi would write. The three ticket messages tell you which stage broke:

| Message | Meaning |
| --- | --- |
| `missing key(s) in connection file: ...` | cv4pve-vdi wrote a file without one of the required keys. It names the keys that are **absent**. |
| `password= is empty: cv4pve-vdi got no VNC ticket from PVE` | PVE refused the ticket. Check that the user holds VM.Console and VM.Audit on the guest, and that the guest is running. |
| `password (VNC ticket) has N unexpected character(s): U+XXXX` | Something other than PVE wrote this file, or the ticket was mangled. Reports the offending code points. |

The rest fail closed on the file itself: unknown or duplicate keys, a second
section, a `[DEFAULT]` section, `type` other than `vnc`, `host` other than
`127.0.0.1`, a port outside 1-65535, a `title` that is not 1-200 printable
ASCII characters, a `delete-this-file` value other than `1`, a file that is
not valid UTF-8 or not valid INI, and a `.vv` over 4096 bytes.

## Why it checks so much of the file

The `.vv` is written from a Proxmox API response, and this script feeds it to a
viewer. So:

- The viewer starts from a list argv. No shell, no `eval`, no `shell=True`, so
  nothing in the file can become command syntax. Printable ASCII `!` through
  `~` is allowed in the ticket on purpose, including characters a shell would
  read. The ticket reaches one place, the 0600 password file, and `configparser`
  with `interpolation=None` round-trips every one of them unchanged.
- The ticket never enters argv, the environment, or any log. The password file
  holds the 8 obfuscated bytes and nothing else. Diagnostics name the failed
  check rather than the bytes that failed it, with two bounded exceptions: the
  charset failure reports code points only, and whitelist-shaped unknown key
  names are echoed.
- `VNC_PASSWORD` and `VNC_USERNAME` are stripped from the child environment.
  TigerVNC prefers those over `-passwd`, so a stale value would silently beat
  the ticket.
- Every check runs before the viewer launches. A file that fails anything gets
  deleted and nothing starts.

## Tests

```sh
python3 -m unittest test_cv4pve_tigervnc_wrapper
```

46 tests, no network, and TigerVNC is never started: `main()` is driven
end to end against `/bin/sh` stubs. One stub records the password file's bytes
and mode, proving the file holds exactly `vncpasswd_obfuscate(ticket)` and
nothing else; another exits 7 to prove the child's exit code passes through;
another kills itself to prove a signaled viewer exits 128+N; and two run the
real script as a subprocess to prove SIGTERM and SIGINT each clean up the
password file on their way out. `find_viewer` always runs for real, pointed at
a stub through `$CV4PVE_TIGERVNC_VIEWER`.

The DES port is checked against the vector documented in TigerVNC's `d3des.c`
(`c95744256a5ed31d`) and cross-checked against `openssl enc -des-ecb`, which the
test skips if this machine's OpenSSL has no DES. TigerVNC's DES consumes each key
byte least-significant-bit-first and ignores the high bit, so a textbook-DES
oracle disagrees with it. The equivalence
`des_vnc(block, key) == std_des(block, bitrev_each_byte(key))` is asserted both
ways.

## Provenance

The DES tables and round function are transcribed from TigerVNC's
`common/rfb/d3des.c`. That file's own header reads, in part:

> This is D3DES (V5.09) by Richard Outerbridge with the double and
> triple-length support removed for use in VNC. Also the bytebit[] array
> has been reversed so that the most significant bit in each byte of the
> key is ignored, not the least significant.
>
> These changes are: Copyright (C) 1999 AT&T Laboratories Cambridge.
> All Rights Reserved.
>
> A portable, public domain, version of the Data Encryption Standard.
> Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.

Outerbridge's implementation is public domain by its own statement. The AT&T
Cambridge reduction is not covered by that grant: it carries its own copyright
line and "All Rights Reserved", with a warranty disclaimer and no copyleft
terms. The encryption half is transcribed unchanged from the file the VNC
ecosystem has distributed since 1999; the decryption half is omitted as
unneeded. That code sits alongside this repo's MIT license on everything else.
TigerVNC itself is GPLv2; outside `d3des.c`, the only thing taken from it is
the fixed 8-byte obfuscation key its `common/rfb/obfuscate.cxx` defines, and
the viewer is a separate process this script only execs.

Everything else was written for this repo. `.vv` field names and the ticket
format come from reading `Corsinvest/cv4pve-api-dotnet`
`RemoteViewerHelper.CreateVncWebSocketBridgeAsync` and `PVE::API2::Nodes.pm` at
the versions named above.
