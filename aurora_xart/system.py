# SPDX-License-Identifier: MIT
"""Reading the system: every path goes through Root, so --root can point the
tool at a tree laid out like a Mac's instead of the running system."""

from __future__ import annotations

import glob
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path

VAR_LIB = "/var/lib"
KEYBAG = "/var/lib/aurora-sep-keybag.bin"
HOST_STATE = "/var/lib/aurora-sep-host-state.bin"
CATACOMB_MASTER = "/var/lib/apple-sep-catacomb-master.bin"
CATACOMB_OWNER = "/var/lib/apple-sep-catacomb-owner.bin"
CATACOMB_USER = "/var/lib/apple-sep-catacomb-user.bin"
REFKEY = "/var/lib/aurora-sep-refkey.bin"
REFKEY_V2 = "/var/lib/aurora-sep-refkey-v2.bin"
LOCKOUT = "/var/lib/aurora-sep-touchid-lockout.bin"
OWNED = "/var/lib/aurora-sep-xart-owned.bin"
ALLOW = "/var/lib/aurora-sep-xart-allow-once.bin"
PREVIOUS = "/var/lib/aurora-sep-xart-policy-previous.bin"
FPRINT = "/var/lib/fprint"
MODPROBE_CONF = "/etc/modprobe.d/aurora-sep.conf"

# What a Touch ID reset moves aside, as install-aurora-sep.sh's
# TOUCHID_STATE_FILES. The keybag is last: a reset that stops partway keeps
# it, so the next boot does not create a second bag next to the old state.
TOUCHID_STATE_FILES = [
    HOST_STATE,
    CATACOMB_MASTER,
    CATACOMB_OWNER,
    CATACOMB_USER,
    REFKEY,
    REFKEY_V2,
    KEYBAG,
]

# The guard's files. A reset keeps them: Linux's records stay Linux's.
GUARD_FILES = [OWNED, ALLOW, PREVIOUS]

# Every Linux-side state file `list` reports.
STATE_FILES = TOUCHID_STATE_FILES[:-1] + [LOCKOUT] + GUARD_FILES + [KEYBAG]

DESCRIPTIONS = {
    HOST_STATE: "host state store",
    CATACOMB_MASTER: "catacomb (master)",
    CATACOMB_OWNER: "catacomb (owner)",
    CATACOMB_USER: "catacomb (user)",
    REFKEY: "machine ref-key",
    REFKEY_V2: "machine ref-key (recovery slot)",
    KEYBAG: "identity keybag slot",
    LOCKOUT: "Touch ID lockout record",
    OWNED: "xART guard list",
    ALLOW: "one-time xART allowance",
    PREVIOUS: "saved previous xART values",
}

# kmod's configuration directories, in its order of precedence.
MODPROBE_DIRS = ["/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d",
                 "/usr/lib/modprobe.d", "/lib/modprobe.d"]
MODULE_NAMES = ("apple_sep", "apple-sep")
PARAMS = {"xart_writes": 1, "provision_keybag": 1, "xart_guard": -1}

CALIBRATION_GLOBS = [
    "/usr/lib/firmware/apple/mesa*.bin",
    "/lib/firmware/apple/mesa*.bin",
    "/var/lib/aurora-sep/firmware/apple/mesa*.bin",
]


@dataclass
class FileRead:
    path: str
    data: bytes | None = None
    error: str | None = None  # None, "missing", "needs root" or a message

    @property
    def exists(self) -> bool:
        return self.error != "missing"


@dataclass
class Param:
    value: int
    source: str


@dataclass
class Diag:
    device: str | None
    attrs: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.attrs.get(name)


class Root:
    def __init__(self, root: str = "/"):
        self.root = Path(root or "/")

    @property
    def is_live(self) -> bool:
        return self.root.resolve() == Path("/")

    def p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def show(self, path: str) -> str:
        """A path as the user reads it: the system path. Under --root the
        command says once that paths are relative to it."""
        return path

    def read(self, path: str, limit: int | None = None) -> FileRead:
        try:
            with open(self.p(path), "rb") as f:
                return FileRead(path, f.read() if limit is None else f.read(limit))
        except FileNotFoundError:
            return FileRead(path, error="missing")
        except PermissionError:
            return FileRead(path, error="needs root")
        except OSError as e:
            return FileRead(path, error=os.strerror(e.errno) if e.errno else str(e))

    def text(self, path: str) -> str | None:
        r = self.read(path)
        if r.data is None:
            return None
        return r.data.decode("utf-8", "replace")

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.p(path))

    def stat(self, path: str) -> os.stat_result | None:
        try:
            return os.lstat(self.p(path))
        except OSError:
            return None

    def glob(self, pattern: str) -> list[str]:
        """System paths matching pattern under the root."""
        base = str(self.root).rstrip("/")
        return sorted(m[len(base):] if base else m for m in glob.glob(str(self.p(pattern))))

    # ---- facts ----------------------------------------------------------

    def compatible(self) -> list[str]:
        for path in ("/proc/device-tree/compatible", "/sys/firmware/devicetree/base/compatible"):
            r = self.read(path)
            if r.data is not None:
                return [s for s in r.data.decode("ascii", "replace").split("\0") if s]
        return []

    def model(self) -> str | None:
        for path in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
            r = self.read(path)
            if r.data is not None:
                return r.data.decode("utf-8", "replace").strip("\0").strip() or None
        return None

    def diag(self) -> Diag:
        dirs = self.glob("/sys/bus/platform/devices/*.sep/diag")
        if not dirs:
            return Diag(None)
        d = dirs[0]
        result = Diag(d.split("/")[-2])
        for attr in self.glob(d + "/*"):
            value = self.text(attr)
            if value is not None:
                result.attrs[attr.rsplit("/", 1)[1]] = value.strip()
        return result

    def module_loaded(self) -> bool:
        return self.exists("/sys/module/apple_sep")

    def cmdline(self) -> str:
        return self.text("/proc/cmdline") or ""

    def modprobe_files(self) -> list[str]:
        """kmod's configuration files in the order it reads them: by name,
        with a file in an earlier directory hiding one of the same name."""
        chosen: dict[str, str] = {}
        for d in MODPROBE_DIRS:
            for path in self.glob(d + "/*.conf"):
                chosen.setdefault(path.rsplit("/", 1)[1], path)
        return [chosen[name] for name in sorted(chosen)]

    def modprobe_options(self) -> list[tuple[str, str, str]]:
        """(param, value, source) for every apple_sep option in modprobe.d."""
        found = []
        for path in self.modprobe_files():
            text = self.text(path)
            if text is None:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                try:
                    words = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if len(words) >= 2 and words[0] == "options" and words[1] in MODULE_NAMES:
                    for word in words[2:]:
                        key, sep, value = word.partition("=")
                        if sep:
                            found.append((key.replace("-", "_"), value, f"{path}:{n}"))
        return found

    def cmdline_options(self) -> list[tuple[str, str, str]]:
        """(param, value, source) for every apple_sep option on the kernel
        command line, which kmod passes to the module like modprobe.d's."""
        found = []
        for word in self.cmdline().split():
            key, sep, value = word.partition("=")
            module, dot, param = key.partition(".")
            if sep and dot and module in MODULE_NAMES:
                found.append((param.replace("-", "_"), value, "kernel command line"))
        return found

    def options(self) -> list[tuple[str, str, str]]:
        """modprobe.d's options, then the command line's: the order kmod
        passes them in (`modprobe -c`), so the last value wins."""
        return self.modprobe_options() + self.cmdline_options()

    def params(self) -> dict[str, Param]:
        """The parameters as configured. A value the running module exposes in
        sysfs replaces the configured one."""
        result = {name: Param(default, "default") for name, default in PARAMS.items()}
        found = [(k, v, s) for k, v, s in self.options() if k in result]
        for name in PARAMS:
            value = self.text(f"/sys/module/apple_sep/parameters/{name}")
            if value is not None:
                found.append((name, value.strip(), "running module"))
        for key, value, source in found:
            number = _number(value)
            if number is not None:
                result[key] = Param(number, source)
        return result

    def read_only_install(self) -> tuple[bool, str | None]:
        """Whether this install keeps the driver read-only, and why.

        install-aurora-sep.sh --read-only writes MODPROBE_CONF with
        xart_writes=0 provision_keybag=0. Owners also use that file to turn
        writes on, so what it sets counts, not that it exists. Elsewhere the
        configured value counts."""
        conf = self.read(MODPROBE_CONF)
        if conf.error not in (None, "missing"):
            return True, f"{self.show(MODPROBE_CONF)} exists but cannot be read ({conf.error})"
        for key, value, source in self.modprobe_options():
            if (source.startswith(MODPROBE_CONF + ":")
                    and key in ("xart_writes", "provision_keybag") and value.strip() == "0"):
                return True, f"{key}={value} in {MODPROBE_CONF}, the read-only install's file"
        params = self.params()
        for key in ("xart_writes", "provision_keybag"):
            if params[key].value == 0:
                return True, f"{key}=0 ({params[key].source})"
        return False, None

    def fprint_dirs(self) -> tuple[list[str], str | None]:
        """Each user's /var/lib/fprint/<user>/apple-sep, and an error if
        /var/lib/fprint could not be listed."""
        base = self.p(FPRINT)
        try:
            users = sorted(os.listdir(base))
        except FileNotFoundError:
            return [], None
        except PermissionError:
            return [], "needs root"
        except OSError as e:
            return [], e.strerror
        found = []
        for user in users:
            d = base / user / "apple-sep"
            if d.is_dir() and not d.is_symlink():
                found.append(f"{FPRINT}/{user}/apple-sep")
        return found, None

    def calibration(self) -> list[str]:
        """Calibration files, each once: /lib is often a link to /usr/lib."""
        found, seen = [], set()
        for pattern in CALIBRATION_GLOBS:
            for path in self.glob(pattern):
                real = os.path.realpath(self.p(path))
                if real not in seen:
                    seen.add(real)
                    found.append(path)
        return found


def _number(value: str) -> int | None:
    """A parameter value as the kernel parses an integer (base 0)."""
    text = value.strip()
    sign, digits = (-1, text[1:]) if text.startswith("-") else (1, text)
    try:
        if digits.lower().startswith("0x"):
            return sign * int(digits[2:], 16)
        if len(digits) > 1 and digits.startswith("0"):
            return sign * int(digits[1:], 8)
        return sign * int(digits, 10)
    except ValueError:
        return None
