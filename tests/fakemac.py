# SPDX-License-Identifier: MIT
"""A Mac's files under a temporary root, built from the driver's formats."""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aurora_xart import cli, formats  # noqa: E402

BOARDS = {
    "m1": (["apple,j313", "apple,t8103", "apple,arm-platform"],
           "Apple MacBook Air (M1, 2020)", "T8103/J313", "0"),
    "m2pro": (["apple,j414s", "apple,t6020", "apple,arm-platform"],
              "Apple MacBook Pro (14-inch, M2 Pro, 2023)", "T6020/J414s", "1"),
    "m3": (["apple,j613", "apple,t8122", "apple,arm-platform"],
           "Apple MacBook Air (13-inch, M3, 2024)", "T8122/J613", "1"),
}

WRAPPED = b"\xa5" * 1500
SECRET = bytes(range(32, 64))
BAG_UUID = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")


def session(n: int) -> bytes:
    return bytes([n]) * 16


class FakeMac:
    def __init__(self, board: str = "m2pro", driver: bool = True, **diag):
        self._tmp = tempfile.TemporaryDirectory(prefix="aurora-xart-test-")
        self.root = Path(self._tmp.name)
        compatible, model, profile, guard = BOARDS[board]
        self.write("/proc/device-tree/compatible", "\0".join(compatible).encode() + b"\0")
        self.write("/proc/device-tree/model", model.encode() + b"\0")
        self.write("/proc/cmdline", b"BOOT_IMAGE=/vmlinuz root=UUID=x rw\n")
        (self.root / "var/lib").mkdir(parents=True, exist_ok=True)
        if driver:
            (self.root / "sys/module/apple_sep/parameters").mkdir(parents=True)
            attrs = {
                "abi": "2", "profile": profile, "boot": "warm", "protocol": "variant5",
                "xart": "enabled", "attach": "attached", "endpoints": "12",
                "keystore": "open", "keybag": "present", "sensor": "unbound",
                "touchid": "unknown", "sensor_attach": "unknown", "restore": "unknown",
                "xart_guard": guard, "xart_guard_list": "loaded" if guard != "0" else "none",
                "xart_guard_refusals": "0",
                "matching": "unverified" if guard != "0" else "usable",
            }
            attrs.update(diag)
            self.set_diag(**attrs)

    def cleanup(self) -> None:
        self._tmp.cleanup()

    def p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def write(self, path: str, data: bytes | str, mode: int = 0o600) -> Path:
        target = self.p(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            os.chmod(target, 0o600)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        os.chmod(target, mode)
        return target

    def read(self, path: str) -> bytes:
        return self.p(path).read_bytes()

    def set_diag(self, **attrs) -> None:
        for name, value in attrs.items():
            path = f"/sys/bus/platform/devices/23d2c0000.sep/diag/{name}"
            if value is None:
                if self.p(path).exists():
                    self.p(path).unlink()
                continue
            self.write(path, f"{value}\n", 0o444)

    # ---- state files ------------------------------------------------------

    def intent(self, unfinished: formats.Unfinished) -> None:
        mark = formats.encode_mark(unfinished)
        self.write("/var/lib/aurora-sep-keybag.bin",
                   formats.keybag_record(formats.STATE_INTENT, uuid=mark))

    def committed(self, state: int = formats.STATE_COMMITTED) -> None:
        self.write("/var/lib/aurora-sep-keybag.bin",
                   formats.keybag_record(state, WRAPPED, BAG_UUID, SECRET))

    def refused(self) -> None:
        self.write("/var/lib/aurora-sep-keybag.bin", formats.keybag_record(formats.STATE_REFUSED))

    def guard_list(self, *sessions: int, extra: bytes = b"") -> None:
        data = b"".join(formats.encode_entry(4, session(n)) for n in sessions)
        self.write("/var/lib/aurora-sep-xart-owned.bin", data + extra)

    def touchid_state(self) -> None:
        """The other files a set-up Touch ID leaves behind."""
        self.write("/var/lib/aurora-sep-host-state.bin", b"S" * 4096)
        for who in ("master", "owner", "user"):
            self.write(f"/var/lib/apple-sep-catacomb-{who}.bin", who.encode() * 40)
        self.write("/var/lib/aurora-sep-refkey.bin", b"R" * 258)
        self.write("/var/lib/aurora-sep-touchid-lockout.bin", formats.lockout_record(False))
        self.write("/var/lib/aurora-sep-xart-allow-once.bin", b"")
        self.write("/var/lib/aurora-sep-xart-policy-previous.bin",
                   formats.previous_record(4, session(9), b"old value"))
        self.write("/usr/lib/firmware/apple/mesa_calibration.bin", b"C" * 64, 0o644)
        for user in ("dj", "root"):
            self.write(f"/var/lib/fprint/{user}/apple-sep/0/7", b"print-" + user.encode())
        self.write("/var/lib/fprint/dj/other-driver/0/1", b"not ours")

    # ---- running the command ----------------------------------------------

    def run(self, *argv: str, runner=None, **kw) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        calls = kw.pop("calls", None)

        def record(cmd, timeout):
            if calls is not None:
                calls.append(list(cmd))
            return 0

        rc = cli.main(["--root", str(self.root), *argv], out=out, err=err,
                      runner=runner or record, sleep=lambda s: None)
        return rc, out.getvalue(), err.getvalue()
