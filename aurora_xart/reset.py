# SPDX-License-Identifier: MIT
"""reset-touchid: start Touch ID over, as install-aurora-sep.sh --reset-touchid does."""

from __future__ import annotations

import textwrap
import time
from collections.abc import Callable

from . import ops, system
from . import state as st
from .ops import Fprintd, Refusal, Runner, move, need_root, unique_dir
from .system import Root

RESET_PREFIX = "/var/lib/aurora-sep-touchid-reset-"

LOST = """\
This removes every enrolled fingerprint on this Mac, and the next boot creates a
new Touch ID keybag:
  - every finger has to be enrolled again;
  - anything sealed with the Secure Enclave (kernel trusted keys) can no longer
    be unsealed;
  - the old keybag, if the enclave has one, stays there unused. It cannot be
    deleted, and the reset cannot be undone.
Kept: Linux's xART guard list and its other files, the Touch ID calibration
and the Touch ID lockout record.
If Touch ID has failed only once, reboot and try it again first: a passing error
looks the same."""


def reset_touchid(root: Root, yes: bool, force: bool, out, err, *,
                  runner: Runner, sleep: Callable[[float], None] = time.sleep,
                  confirm: Callable[[str, str], bool] | None = None,
                  stamp: str | None = None) -> int:
    state = st.inspect(root)
    if not state.is_apple:
        raise Refusal("this is not an Apple silicon Mac")
    read_only, why = state.read_only
    if read_only:
        raise Refusal(f"this Mac was installed read-only ({why}): a new keybag needs enclave "
                      "writes. Remove that setting first if you mean to allow them.")
    if not any(root.exists(f) for f in system.TOUCHID_STATE_FILES):
        raise Refusal("no Touch ID state on this Mac; nothing to reset")
    need_root(root, "reset-touchid")

    if not state.driver_running:
        raise Refusal("the Touch ID driver is not running (no SEP diagnostics). Boot the Aurora "
                      "kernel first.")
    if state.diag.get("xart") == "disabled":
        raise Refusal("the driver runs with xART writes disabled this boot, so it could not "
                      "create a new keybag")

    services = Fprintd(root, runner, sleep, out)
    # The driver loads a stored keybag, and reports failed if that does not
    # work, only when the sensor is first opened.
    if not state.stuck and state.diag.get("touchid") == "unknown":
        services.open_sensor()
        state = st.inspect(root)
    keybag = state.diag.get("keybag")
    if not state.stuck and keybag != "failed":
        if not force:
            raise Refusal(f"the Touch ID keybag is not broken (driver reports keybag={keybag}, "
                          f"touchid={state.diag.get('touchid')}). A reset would throw away a "
                          "working keybag. If Touch ID still fails and you mean it, run again "
                          "with --force.")
        print(f"warning: resetting although the driver reports keybag={keybag} (--force)",
              file=err)

    for finding in state.findings:
        if finding.level == "error":
            print(textwrap.fill(f"Why: {finding.message}", 79, subsequent_indent="  "),
                  file=out)
    print(LOST, file=out)
    confirm = confirm or ops.confirm_on_tty
    if not yes and not confirm("Type RESET to continue: ", "RESET"):
        raise Refusal("not reset")

    # Until the reboot nothing may touch the sensor: a match or enrolment
    # would write new state behind the move. The runtime mask ends at boot.
    services.stop()
    sources = []
    fprint, fprint_error = root.fprint_dirs()
    if fprint_error:
        services.release()
        raise Refusal(f"cannot list {root.show(system.FPRINT)} ({fprint_error}); nothing moved")
    sources += fprint
    sources += [f for f in system.TOUCHID_STATE_FILES if root.exists(f)]
    dest = unique_dir(root, RESET_PREFIX, stamp)
    moved: list[tuple[str, str]] = []
    for src in sources:
        if src.startswith(system.FPRINT + "/"):
            to = f"{dest}/fprint/{src.split('/')[-2]}/apple-sep"
        else:
            to = f"{dest}/{src.rsplit('/', 1)[1]}"
        try:
            move(root, src, to)
        except OSError as e:
            failed = []
            for back_src, back_to in reversed(moved):
                try:
                    move(root, back_to, back_src)
                except OSError as e2:
                    failed.append(f"{root.show(back_src)} (still in {root.show(back_to)}: {e2})")
            services.release()
            for f in failed:
                print(f"error: could not put back {f}", file=err)
            raise Refusal(f"could not move {root.show(src)} ({e.strerror or e}); "
                          + ("put back everything already moved, so Touch ID is as it was"
                             if not failed else "some files could not be put back, see above")
                          ) from e
        moved.append((src, to))
        print(f"moved {root.show(src)} -> {root.show(to)}", file=out)

    print(f"Moved the Touch ID state to {root.show(dest)}", file=out)
    print("Reboot now. Touch ID creates its new keybag during boot; then enroll your fingers "
          "again.", file=out)
    if services.masked:
        print("Until you reboot fprintd stays masked.", file=out)
    return 0
