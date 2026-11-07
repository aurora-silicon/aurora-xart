# SPDX-License-Identifier: MIT
"""What the driver and its host files say, and what that means in plain words."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from . import formats, platform, system
from .system import Root

RESET_HINT = "Run `sudo aurora-xart reset-touchid` to start Touch ID over."


@dataclass
class Finding:
    level: str  # "ok", "info", "warn" or "error"
    code: str
    message: str
    action: str | None = None

    def json(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message,
                "action": self.action}


@dataclass
class FileInfo:
    path: str
    description: str
    exists: bool
    size: int | None = None
    mtime: float | None = None

    def json(self) -> dict:
        return {"path": self.path, "description": self.description, "exists": self.exists,
                "size": self.size,
                "mtime": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.mtime))
                if self.mtime is not None else None}


@dataclass
class Guard:
    level: int
    source: str  # "driver" or "configuration"
    list_state: str | None = None  # the driver's xart_guard_list
    refusals: int | None = None
    matching: str | None = None
    # The list length the driver judges an unfinished create by this boot:
    # None without a guard or a list, or when it cannot be read here.
    listed: int | None = None
    listed_known: bool = True


@dataclass
class State:
    root: Root
    model: str | None
    compatible: list[str]
    chip: str | None
    profile: platform.Profile | None
    diag: system.Diag
    module_loaded: bool
    params: dict[str, system.Param]
    read_only: tuple[bool, str | None]
    guard: Guard
    keybag_file: system.FileRead
    keybag: formats.KeybagSlot | None
    list_file: system.FileRead
    guard_list: formats.GuardList | None
    allow_file: system.FileRead
    allowance: formats.Allowance | None
    allowance_problem: str | None
    previous_file: system.FileRead
    previous: list[formats.PreviousValue] | None
    previous_leftover: int
    lockout_file: system.FileRead
    files: list[FileInfo]
    fprint_dirs: list[str]
    fprint_error: str | None
    calibration: list[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_apple(self) -> bool:
        return any(c.startswith("apple,") for c in self.compatible)

    @property
    def driver_running(self) -> bool:
        return self.diag.get("keybag") is not None

    @property
    def retry(self) -> bool | None:
        """Whether the driver sends an unfinished create again, or None."""
        if self.keybag is None or self.keybag.intent is None:
            return None
        if not self.guard.listed_known:
            return None
        return formats.may_retry_create(self.keybag.intent, self.guard.listed)

    @property
    def stuck(self) -> bool:
        """The slot keeps the driver from loading or creating a keybag."""
        kb = self.keybag
        if kb is None:
            return False
        if kb.driver_read in ("EINVAL", "ENOTSYNC"):
            return True
        if kb.driver_read == "EEXIST":
            return self.retry is not True
        return False


def _info(root: Root, path: str) -> FileInfo:
    st = root.stat(path)
    if st is None:
        return FileInfo(path, system.DESCRIPTIONS.get(path, ""), False)
    return FileInfo(path, system.DESCRIPTIONS.get(path, ""), True, st.st_size, st.st_mtime)


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def inspect(root: Root) -> State:
    compatible = root.compatible()
    profile = platform.select(compatible)
    diag = root.diag()
    params = root.params()

    level = _int(diag.get("xart_guard"))
    if level is not None:
        guard = Guard(level, "driver", diag.get("xart_guard_list"),
                      _int(diag.get("xart_guard_refusals")), diag.get("matching"))
    else:
        level = platform.guard_level(params["xart_guard"].value,
                                     profile.guard_default if profile else 0)
        if params["xart_writes"].value == 0 or diag.get("xart") == "disabled":
            level = 0
        guard = Guard(level, "configuration")

    list_file = root.read(system.OWNED)
    guard_list = formats.decode_list(list_file.data) if list_file.data is not None else None
    if guard.level == 0 or guard.list_state == "unavailable":
        guard.listed = None
    elif guard_list is not None:
        guard.listed = guard_list.driver_count
    elif list_file.error == "missing":
        # The guard creates an empty list when it opens.
        guard.listed = 0
    else:
        guard.listed_known = False

    keybag_file = root.read(system.KEYBAG)
    keybag = formats.decode_keybag(keybag_file.data) if keybag_file.data is not None else None

    allow_file = root.read(system.ALLOW)
    allowance, allowance_problem = (formats.decode_allowance(allow_file.data)
                                    if allow_file.data is not None else (None, None))
    previous_file = root.read(system.PREVIOUS)
    previous, leftover = (formats.decode_previous(previous_file.data)
                          if previous_file.data is not None else (None, 0))
    fprint_dirs, fprint_error = root.fprint_dirs()

    state = State(
        root=root, model=root.model(), compatible=compatible, chip=platform.chip(compatible),
        profile=profile, diag=diag, module_loaded=root.module_loaded(), params=params,
        read_only=root.read_only_install(), guard=guard,
        keybag_file=keybag_file, keybag=keybag, list_file=list_file, guard_list=guard_list,
        allow_file=allow_file, allowance=allowance, allowance_problem=allowance_problem,
        previous_file=previous_file, previous=previous, previous_leftover=leftover,
        lockout_file=root.read(system.LOCKOUT),
        files=[_info(root, p) for p in system.STATE_FILES],
        fprint_dirs=fprint_dirs, fprint_error=fprint_error, calibration=root.calibration(),
    )
    state.findings = diagnose(state)
    return state


# ---- plain words -------------------------------------------------------------


def _stuck_reason(state: State) -> str:
    kb = state.keybag
    intent = kb.intent
    g = state.guard
    if intent is None:
        return {
            "EINVAL": "its intent record is damaged, so the driver cannot tell what it recorded",
            "EEXIST": "its intent carries a mark no driver writes",
        }.get(kb.intent_error or "", "its intent cannot be read")
    if intent.kind == "unguarded":
        return ("it was sent with no xART guard running, so the records the enclave made then "
                "were never listed")
    if g.level == 0:
        param = state.params["xart_guard"]
        if param.value == 0:
            why = f"xart_guard=0 is set ({param.source})"
        elif state.params["xart_writes"].value == 0 or state.diag.get("xart") == "disabled":
            why = "xART writes are disabled"
        elif state.profile in (platform.T8103, platform.T6000):
            why = "xart_guard defaults to 0 on M1 Macs since linux#1049"
        elif state.profile is not None and state.profile.guard_default == 0:
            why = f"xart_guard defaults to 0 on the {state.profile.chip}"
        else:
            why = "the guard is off"
        return (f"it was {intent.describe()}, but this kernel runs the Mac without the guard "
                f"({why}), so it has no list to check the create against")
    if g.listed is None:
        return "the guard could not load Linux's list, so nothing proves the create left no bag"
    if intent.kind == "unmarked":
        return (f"an older driver wrote it without recording Linux's list, and the list is not "
                f"empty now ({g.listed} entries)")
    if g.listed > intent.entries:
        return (f"Linux's list grew from {intent.entries} to {g.listed} entries since, so the "
                f"create may have left a record")
    return (f"Linux's list is shorter than when the create was sent ({g.listed}, was "
            f"{intent.entries}): it was rolled back or replaced")


def diagnose(state: State) -> list[Finding]:
    out: list[Finding] = []
    d = state.diag
    root = state.root
    kb = state.keybag

    if not state.is_apple:
        out.append(Finding("error", "not-apple-silicon",
                           "This is not an Apple silicon Mac: the device tree names no apple, "
                           "machine."))
        return out
    if state.profile is None:
        chip = state.chip or "unknown chip"
        out.append(Finding("info", "no-profile",
                           f"The SEP driver has no profile for this Mac ({chip}), so it does "
                           "not bind and Touch ID is unavailable."))

    if not state.driver_running:
        if state.module_loaded:
            out.append(Finding("warn", "driver-unbound",
                               "apple_sep is loaded but not bound to the Secure Enclave (no diag "
                               "attributes).", "Check `journalctl -b -k | grep apple_sep`."))
        elif state.profile is not None:
            out.append(Finding("warn", "driver-not-running",
                               "The SEP driver is not running (no "
                               "/sys/bus/platform/devices/*.sep/diag).",
                               "Boot an Aurora kernel and check `systemctl status aurora-sep`."))
    else:
        if d.get("attach") == "failed":
            out.append(Finding("error", "attach-failed",
                               "The Secure Enclave never answered the driver's attach this boot; "
                               "the key store and Touch ID cannot run until the next boot."))
        if d.get("keystore") == "closed":
            out.append(Finding("warn", "keystore-closed",
                               "The boot-time bring-up ended without opening the key store; "
                               "keybag and Touch ID operations are unavailable this boot."))

    # The identity keybag slot.
    kf = state.keybag_file
    if kf.error == "needs root":
        msg = f"The keybag slot ({root.show(system.KEYBAG)}) is readable by root only."
        if d.get("keybag") == "failed":
            msg = ("The driver reports the identity keybag as failed; reading why needs root "
                   f"({root.show(system.KEYBAG)}).")
        out.append(Finding("warn" if d.get("keybag") == "failed" else "info", "needs-root", msg,
                           "Run `sudo aurora-xart status`."))
    elif kf.error not in (None, "missing"):
        out.append(Finding("warn", "keybag-unreadable",
                           f"The keybag slot cannot be read: {kf.error}."))
    elif kf.error == "missing":
        if d.get("keybag") == "missing" or not state.driver_running:
            note = ""
            if state.params["provision_keybag"].value == 0:
                note = " provision_keybag=0, so the driver does not create one."
            out.append(Finding("info", "keybag-none",
                               "No identity keybag is stored yet: Touch ID is not set up." + note))
    elif kb is not None:
        if kb.driver_read == "present":
            if d.get("keybag") == "failed":
                out.append(Finding(
                    "error", "keybag-does-not-load",
                    f"A keybag is stored ({kb.provenance} UUID), but the driver could not load "
                    "it this boot. This happens to an M2 Pro or Max enrolled on system firmware "
                    "26.2 or earlier and then updated.",
                    "If Touch ID still fails after a reboot: " + RESET_HINT))
            else:
                out.append(Finding("ok", "keybag-committed",
                                   f"The identity keybag is stored and intact ({kb.provenance} "
                                   "UUID)."))
        elif kb.state_name == "refused":
            out.append(Finding("info", "keybag-refused",
                               "The enclave refused the last keybag create, so nothing was "
                               "created; the driver tries again at the next boot."))
        elif kb.driver_read == "EEXIST" and kb.state_name == "intent":
            if state.retry is True:
                out.append(Finding(
                    "info", "keybag-intent-retry",
                    f"An earlier keybag create never finished, but Linux's list shows it left "
                    f"nothing (intent {kb.intent}, {state.guard.listed} listed). The driver "
                    "sends the create again at the next boot by itself.", "Reboot."))
            elif state.retry is None and kb.intent is not None:
                out.append(Finding(
                    "warn", "keybag-intent",
                    f"An earlier keybag create never finished (intent {kb.intent}); whether the "
                    "driver may send it again depends on Linux's list, which needs root to "
                    "read.", "Run `sudo aurora-xart status`."))
            else:
                out.append(Finding(
                    "error", "keybag-intent-stuck",
                    "An earlier keybag create never finished, and the driver cannot prove it "
                    f"left no bag: {_stuck_reason(state)}. So it refuses to create another, on "
                    "every boot (\"identity keybag state is ambiguous: EEXIST\"), and Touch ID "
                    "and trusted keys stay down.", RESET_HINT))
        elif kb.driver_read == "EEXIST":
            out.append(Finding("error", "keybag-unknown-state",
                               f"The keybag slot holds a state no driver writes ({kb.problem}); "
                               "the driver treats it as an unfinished create and refuses to "
                               "create another.", RESET_HINT))
        elif kb.driver_read == "ENOTSYNC":
            out.append(Finding("error", "keybag-old-version",
                               f"The keybag slot is in a {kb.problem}; the driver cannot read it "
                               "and does not create another.", RESET_HINT))
        else:
            out.append(Finding("error", "keybag-damaged",
                               f"The keybag slot is damaged: {kb.problem}. The driver reports "
                               "the keybag state as ambiguous (EINVAL) and does not create "
                               "another.", RESET_HINT))

    if (d.get("touchid") == "failed" and d.get("keybag") == "missing"
            and (d.get("xart") == "disabled" or state.read_only[0])):
        out.append(Finding("info", "not-provisioned",
                           "Touch ID reads failed because this is a read-only install: no "
                           "keybag was provisioned. That is not a fault."))

    # The xART guard.
    g = state.guard
    if g.level and g.list_state == "unavailable":
        out.append(Finding("error", "guard-list-unavailable",
                           f"The xART guard could not load Linux's list "
                           f"({root.show(system.OWNED)}): every session record that existed at "
                           "boot is protected and no new one can be written, so Touch ID "
                           "writes fail.", "Check that file's permissions, then reboot."))
    if g.refusals:
        out.append(Finding("warn", "guard-refused",
                           f"The xART guard refused {g.refusals} of the enclave's writes this "
                           "boot, so a fingerprint match cannot save its state (matching "
                           "blocked). If Touch ID on this Mac was set up with the guard off, "
                           "or before the guard existed, its records are not on Linux's list.",
                           "See XART-SAFETY.md, \"Recovery when the guard refuses\"; a reset "
                           "does not help here."))
    gl = state.guard_list
    lf = state.list_file
    if gl is not None:
        if gl.too_long:
            out.append(Finding("error", "guard-list-too-long",
                               f"Linux's list holds {gl.whole} entries, more than the "
                               f"{formats.MAX_ENTRIES} the driver opens; the guard runs without "
                               "it."))
        if gl.torn:
            out.append(Finding("info", "guard-list-torn",
                               f"Linux's list has {gl.torn} torn entr"
                               f"{'y' if gl.torn == 1 else 'ies'}, which the driver ignores."))
        if gl.tail_bytes:
            out.append(Finding("info", "guard-list-tail",
                               f"Linux's list ends in {gl.tail_bytes} bytes of a torn append; "
                               "the next new record overwrites them."))
    elif lf.error == "needs root" and g.level:
        out.append(Finding("info", "needs-root",
                           f"Linux's list ({root.show(system.OWNED)}) is readable by root only.",
                           "Run `sudo aurora-xart list`."))
    if state.allowance is not None:
        out.append(Finding("info", "allowance-armed",
                           f"A one-time allowance is armed for the next boot: "
                           f"{state.allowance.describe()}, for a boot policy change."))
    elif state.allowance_problem:
        out.append(Finding("warn", "allowance-damaged",
                           f"The one-time allowance file is {state.allowance_problem}."))

    if state.read_only[0]:
        out.append(Finding("info", "read-only",
                           f"Read-only install: {state.read_only[1]}. The driver attaches and "
                           "reports but creates no keybag."))
    if state.lockout_file.data is not None and formats.lockout_locked(state.lockout_file.data):
        out.append(Finding("info", "touchid-locked",
                           "Touch ID is locked after failed matches; the next password "
                           "authentication unlocks it."))
    return out


def worst(findings: list[Finding]) -> str:
    order = ["ok", "info", "warn", "error"]
    return max((f.level for f in findings), key=order.index, default="ok")


def file_age(path_mtime: float | None) -> str:
    if path_mtime is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(path_mtime))


def geteuid() -> int:
    return os.geteuid()
