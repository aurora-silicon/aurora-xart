# SPDX-License-Identifier: MIT
"""The aurora-xart command line."""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time

from . import __version__, formats, ops, system
from . import state as st
from .reset import reset_touchid
from .system import Root

DESCRIPTION = """\
Inspect and manage the Linux side of the Secure Enclave and xART state on an
Aurora Linux install, in the spirit of xartutil on macOS.

The Secure Enclave keeps its anti-replay state in xART, a store on the iBoot
system container that every OS on the Mac shares. Linux's driver, apple_sep,
keeps its own state in /var/lib: the Touch ID identity keybag slot, the
catacombs, the machine ref-key and the xART guard's list of the session
records Linux created. aurora-xart reads that state, explains it, and can move
the Touch ID state aside to start Touch ID over. It never talks to the
enclave, never writes xART and never deletes a file.
"""

FILES = "\n".join(f"  {path:<46}{what}" for path, what in (
    (system.KEYBAG, "the identity keybag slot"),
    (system.OWNED, "Linux's xART records (the guard list)"),
    (system.ALLOW, "the one-time allowance"),
    (system.PREVIOUS, "saved previous values"),
    (system.MODPROBE_CONF, "a read-only install's settings"),
    ("/sys/bus/platform/devices/*.sep/diag/", "the driver's diagnostics"),
))

EPILOG = f"""\
commands:
  status          The driver's state from sysfs, the platform, the xART guard
                  level and the module parameters, and in plain words what
                  is wrong, if anything, and what to do. --json for scripts.
  list            Linux's xART records from the guard list (kind and session
                  id, no key material), the one-time allowance, the saved
                  previous values, the keybag slot and which state files
                  exist. --json for scripts.
  reset-touchid   Start Touch ID over when its keybag is stuck or no longer
                  loads. Refuses on a read-only install, when the driver is
                  not running, and when the keybag works (unless --force).
                  Asks you to type RESET (unless --yes), stops fprintd, and
                  moves the Touch ID state and each user's prints into
                  /var/lib/aurora-sep-touchid-reset-<time>/, putting
                  everything back if a move fails. Keeps the guard list and
                  the calibration. Reboot afterwards and enroll again.

status and list run without root where the files allow and say when root is
needed; reset-touchid needs root. There is no backup or restore: the enclave's
state is anti-replay protected, so saved Linux-side state cannot be put back
into use. --root DIR runs a command against the files under DIR, laid out as
on a Mac, instead of this system, and leaves this system's services alone.

exit status:
  0  nothing wrong found, or the command did what it was asked
  1  status or list found a problem that needs action
  2  the command refused, or a usage error

files:
{FILES}

The formats follow aurora-silicon/linux at {formats.KERNEL_COMMIT[:12]}.
See XART-SAFETY.md in aurora-sep's documentation for the xART guard.
"""


def _hex(b: bytes | None) -> str | None:
    return b.hex() if b is not None else None


def _keybag_json(s: st.State, with_uuid: bool) -> dict:
    kb, f = s.keybag, s.keybag_file
    result = {"path": s.root.show(system.KEYBAG), "error": f.error}
    if kb is not None:
        result.update({
            "size": kb.size, "state": kb.state_name, "raw_state": kb.state,
            "provenance": kb.provenance, "driver_read": kb.driver_read,
            "intent": str(kb.intent) if kb.intent else None, "intent_error": kb.intent_error,
            "retry": s.retry, "problem": kb.problem,
            "wrapped_len": kb.wrapped_len, "secret_len": kb.secret_len,
        })
        if with_uuid:
            result["uuid"] = _hex(kb.uuid)
    return result


def status_json(s: st.State) -> dict:
    g = s.guard
    return {
        "tool": f"aurora-xart {__version__}",
        "kernel_formats": formats.KERNEL_COMMIT,
        "root": str(s.root.root),
        "platform": {"model": s.model, "compatible": s.compatible, "chip": s.chip,
                     "profile": s.profile.name if s.profile else None,
                     "guard_default": s.profile.guard_default if s.profile else None},
        "driver": {"running": s.driver_running, "module_loaded": s.module_loaded,
                   "device": s.diag.device, "diag": s.diag.attrs},
        "params": {k: {"value": v.value, "source": v.source} for k, v in s.params.items()},
        "guard": {"level": g.level, "source": g.source, "list": g.list_state,
                  "refusals": g.refusals, "matching": g.matching,
                  "listed": g.listed if g.listed_known else "unknown"},
        "read_only": {"value": s.read_only[0], "why": s.read_only[1]},
        "keybag": _keybag_json(s, False),
        "findings": [f.json() for f in s.findings],
        "verdict": st.worst(s.findings),
    }


def list_json(s: st.State) -> dict:
    gl = s.guard_list
    lst = {"path": s.root.show(system.OWNED), "error": s.list_file.error}
    if gl is not None:
        lst.update({
            "size": gl.size, "entries": gl.whole, "records": len(gl.records), "torn": gl.torn,
            "repeated": gl.repeated, "tail_bytes": gl.tail_bytes, "too_long": gl.too_long,
            "items": [{"index": e.index, "kind": e.kind, "session": e.session,
                       "torn": e.kind is None, "repeated": e.repeated} for e in gl.entries],
        })
    allow = {"path": s.root.show(system.ALLOW), "error": s.allow_file.error,
             "problem": s.allowance_problem,
             "armed": None if s.allowance is None else
             {"kind": s.allowance.kind, "session": s.allowance.session}}
    prev = {"path": s.root.show(system.PREVIOUS), "error": s.previous_file.error,
            "leftover_bytes": s.previous_leftover,
            "records": None if s.previous is None else
            [{"kind": p.kind, "session": p.session, "length": p.length, "crc_ok": p.crc_ok}
             for p in s.previous]}
    lockout = None
    if s.lockout_file.data is not None:
        lockout = formats.lockout_locked(s.lockout_file.data)
    return {
        "tool": f"aurora-xart {__version__}",
        "kernel_formats": formats.KERNEL_COMMIT,
        "root": str(s.root.root),
        "guard_list": lst, "allowance": allow, "previous": prev,
        "keybag": _keybag_json(s, True),
        "touchid_locked": lockout,
        "files": [dict(f.json(), path=s.root.show(f.path)) for f in s.files],
        "fprint": {"dirs": [s.root.show(d) for d in s.fprint_dirs], "error": s.fprint_error},
        "calibration": [s.root.show(c) for c in s.calibration],
        "findings": [f.json() for f in s.findings],
    }


def _row(out, label: str, text: str) -> None:
    lines = text.split("\n")
    print(f"{label:<13}{lines[0]}", file=out)
    for line in lines[1:]:
        print(f"{'':<13}{line}", file=out)


def _keybag_text(s: st.State) -> str:
    f, kb = s.keybag_file, s.keybag
    if f.error == "missing":
        return "none stored"
    if f.error:
        return f"unreadable ({f.error})"
    if kb.driver_read == "present":
        return f"committed, {kb.provenance} UUID ({kb.size} bytes, checksum ok)"
    if kb.state_name == "refused":
        return "refused (the enclave created nothing; the next boot tries again)"
    if kb.state_name == "intent":
        if kb.intent is None:
            return f"intent, damaged ({kb.problem})"
        retry = {True: "the driver sends it again", False: "the driver will not send it again",
                 None: "needs root to judge"}[s.retry]
        return f"intent: an unfinished create, {kb.intent.describe()}\n({kb.intent}; {retry})"
    return f"{kb.state_name}: {kb.problem}"


def _list_summary(s: st.State) -> str:
    f, gl = s.list_file, s.guard_list
    if f.error == "missing":
        return "none (the guard creates it when it first runs)"
    if f.error:
        return f"unreadable ({f.error})"
    parts = [f"{len(gl.records)} record{'s' if len(gl.records) != 1 else ''}"]
    if gl.torn:
        parts.append(f"{gl.torn} torn")
    if gl.repeated:
        parts.append(f"{gl.repeated} repeated")
    if gl.tail_bytes:
        parts.append(f"{gl.tail_bytes}-byte torn tail")
    return ", ".join(parts) + f" ({gl.size} bytes)"


def print_findings(s: st.State, out) -> None:
    shown = [f for f in s.findings if f.level != "ok"]
    print(file=out)
    if not shown:
        print("Nothing wrong found.", file=out)
        return
    for f in shown:
        tag = {"info": "note", "warn": "warning", "error": "PROBLEM"}[f.level]
        print(textwrap.fill(f"{tag}: {f.message}", 79, subsequent_indent="  "), file=out)
        if f.action:
            print(textwrap.fill(f.action, 79, initial_indent="  -> ",
                                subsequent_indent="     "), file=out)


def print_status(s: st.State, out) -> None:
    d = s.diag
    compat = " ".join(s.compatible[:2]) if s.compatible else "no device tree"
    _row(out, "Platform", f"{s.model or 'unknown model'}"
         + (f", {s.chip}" if s.chip else "") + f" ({compat})")
    if s.profile:
        _row(out, "SEP profile", f"{s.profile.name}, {s.profile.bootstrap} boot, xART guard "
             f"default {s.profile.guard_default}")
    else:
        _row(out, "SEP profile", "none: the driver does not bind on this Mac")
    if s.driver_running:
        a = d.attrs
        _row(out, "Driver", f"apple_sep on {d.device}, diag ABI {a.get('abi', '?')}, profile "
             f"{a.get('profile', '?')}\n"
             + ", ".join(f"{k} {a[k]}" for k in ("attach", "endpoints", "keystore", "keybag")
                         if k in a) + "\n"
             + ", ".join(f"{k} {a[k]}" for k in ("touchid", "sensor", "sensor_attach", "restore")
                         if k in a))
        _row(out, "xART", f"writes {a.get('xart', '?')}")
    else:
        _row(out, "Driver", "not running" + (" (module loaded, not bound)" if s.module_loaded
                                             else ""))
    g = s.guard
    guard = f"level {g.level}" + (" (none)" if g.level == 0 else "")
    if g.source == "driver":
        guard += ", as the driver reports it"
        if g.level:
            guard += f"\nlist {g.list_state}, {g.refusals} refused, matching {g.matching}"
    else:
        guard += ", from the configuration (the driver is not reporting)"
    _row(out, "xART guard", guard)
    params = []
    for name, p in s.params.items():
        note = p.source
        if name == "xart_guard" and p.value < 0:
            note += ": the platform's level"
        params.append(f"{name + '=' + str(p.value):<20} {note}")
    _row(out, "Parameters", "\n".join(params))
    ro, why = s.read_only
    _row(out, "Install", f"read-only ({why})" if ro else "writable")
    _row(out, "Keybag slot", _keybag_text(s))
    _row(out, "Guard list", _list_summary(s))
    print_findings(s, out)


def print_list(s: st.State, out) -> None:
    root = s.root
    gl = s.guard_list
    print(f"Linux's xART records ({root.show(system.OWNED)}): {_list_summary(s)}", file=out)
    if gl is not None and gl.entries:
        print(f"  {'#':>4}  kind  session id", file=out)
        for e in gl.entries:
            if e.kind is None:
                print(f"  {e.index:>4}  -     torn entry, ignored by the driver", file=out)
            else:
                print(f"  {e.index:>4}  {e.kind:<4}  {e.session}"
                      + ("  (repeated)" if e.repeated else ""), file=out)
    print(file=out)
    if s.allow_file.error == "missing" or (s.allowance is None and not s.allowance_problem
                                          and s.allow_file.data is not None):
        allow = "none armed"
    elif s.allow_file.error:
        allow = f"unreadable ({s.allow_file.error})"
    elif s.allowance_problem:
        allow = s.allowance_problem
    else:
        allow = f"armed for the next boot: {s.allowance.describe()}"
    print(f"One-time allowance ({root.show(system.ALLOW)}): {allow}", file=out)
    pf = s.previous_file
    if pf.error:
        prev = "none" if pf.error == "missing" else f"unreadable ({pf.error})"
        print(f"Saved previous values ({root.show(system.PREVIOUS)}): {prev}", file=out)
    else:
        print(f"Saved previous values ({root.show(system.PREVIOUS)}): {len(s.previous)} "
              "(values not shown)", file=out)
        for p in s.previous:
            print(f"        kind {p.kind}  {p.session}  {p.length} bytes"
                  + ("" if p.crc_ok else "  CHECKSUM MISMATCH"), file=out)
        if s.previous_leftover:
            print(f"        {s.previous_leftover} bytes at the end do not form a record",
                  file=out)
    print(file=out)
    kb_text = _keybag_text(s).replace("\n", "\n             ")
    print(f"Keybag slot ({root.show(system.KEYBAG)}): {kb_text}", file=out)
    if s.keybag is not None and s.keybag.uuid is not None:
        print(f"             UUID {s.keybag.uuid.hex()}", file=out)
    print(file=out)
    print("State files:", file=out)
    for info in s.files:
        if info.exists:
            print(f"  present  {root.show(info.path):<46} {info.size:>9} B  "
                  f"{st.file_age(info.mtime)}  {info.description}", file=out)
        else:
            print(f"  absent   {root.show(info.path):<46} {'':>9}    {'':16}  "
                  f"{info.description}", file=out)
    if s.fprint_error:
        print(f"  prints   {root.show(system.FPRINT)}: {s.fprint_error}", file=out)
    elif s.fprint_dirs:
        for d in s.fprint_dirs:
            n = len(ops.tree_files(root.p(d)))
            print(f"  prints   {root.show(d)} ({n} file{'s' if n != 1 else ''})", file=out)
    else:
        print("  prints   none for the Apple sensor", file=out)
    if s.calibration:
        for c in s.calibration:
            print(f"  calibration  {root.show(c)}", file=out)
    else:
        print("  calibration  none found", file=out)
    if s.lockout_file.data is not None:
        locked = formats.lockout_locked(s.lockout_file.data)
        print(f"  Touch ID lockout: {'locked' if locked else 'not locked'}", file=out)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aurora-xart", description=DESCRIPTION, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"aurora-xart {__version__}")
    p.add_argument("--root", default="/", metavar="DIR",
                   help="work on the files under DIR instead of this system")
    sub = p.add_subparsers(dest="command", metavar="command")
    for name, text in (("status", "the driver's state and what it means"),
                       ("list", "Linux's xART records and state files")):
        c = sub.add_parser(name, help=text, description=text)
        c.add_argument("--json", action="store_true", help="print JSON")
    c = sub.add_parser("reset-touchid", help="start Touch ID over (root)",
                       description="Start Touch ID over: move the Touch ID state aside so the "
                       "next boot creates a new keybag. " + "See aurora-xart --help.")
    c.add_argument("--yes", action="store_true", help="do not ask for RESET")
    c.add_argument("--force", action="store_true", help="reset even a keybag that works")
    return p


def main(argv: list[str] | None = None, out=None, err=None,
         runner: ops.Runner = ops.run, sleep=time.sleep) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    p = parser()
    args = p.parse_args(argv)
    if args.command is None:
        args.command, args.json = "status", False
    root = Root(args.root)
    if not root.is_live and not getattr(args, "json", False):
        print(f"--root: the files under {root.root}; paths below are relative to it", file=out)
    try:
        if args.command in ("status", "list"):
            s = st.inspect(root)
            if args.json:
                data = status_json(s) if args.command == "status" else list_json(s)
                json.dump(data, out, indent=2)
                out.write("\n")
            elif args.command == "status":
                print_status(s, out)
            else:
                print_list(s, out)
                print_findings(s, out)
            return 1 if st.worst(s.findings) == "error" else 0
        if args.command == "reset-touchid":
            return reset_touchid(root, args.yes, args.force, out, err, runner=runner,
                                 sleep=sleep)
    except ops.Refusal as e:
        print(f"aurora-xart: {e}", file=err)
        return 2
    except KeyboardInterrupt:
        print("aurora-xart: interrupted", file=err)
        return 2
    return 2
