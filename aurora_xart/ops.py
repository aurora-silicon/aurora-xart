# SPDX-License-Identifier: MIT
"""Helpers the state-changing commands share: services, moves, prompts."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from .system import Root


class Refusal(Exception):
    """A state-changing command stops before (or instead of) changing anything."""


Runner = Callable[[Sequence[str], float | None], int]


def run(argv: Sequence[str], timeout: float | None = None) -> int:
    try:
        return subprocess.run(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 127


def need_root(root: Root, what: str) -> None:
    if root.is_live and os.geteuid() != 0:
        raise Refusal(f"{what} needs root: run it with sudo")


def confirm_on_tty(prompt: str, word: str) -> bool:
    """Asks on the terminal, not stdin, which may be a pipe."""
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline().strip() == word
    except OSError as e:
        raise Refusal("no terminal to confirm on; run again with --yes") from e


def unique_dir(root: Root, prefix: str, stamp: str | None = None) -> str:
    """Creates prefix-<time> (or -<time>-N), root-only, and returns its system path."""
    stamp = stamp or time.strftime("%Y%m%d-%H%M%S")
    for n in range(100):
        path = f"{prefix}{stamp}" + (f"-{n}" if n else "")
        try:
            os.mkdir(root.p(path), 0o700)
            return path
        except FileExistsError:
            continue
    raise Refusal(f"could not create a new {prefix}{stamp} directory")


def move(root: Root, src: str, dst: str) -> None:
    """Renames src to dst. Never copies and removes: a move to another file
    system is refused, so nothing is ever deleted."""
    target = root.p(dst)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.path.lexists(target):
        raise FileExistsError(f"{dst} already exists")
    os.rename(root.p(src), target)


class Fprintd:
    """Keeps fprintd, and with it the sensor, still while files move."""

    UNIT = "fprintd.service"

    def __init__(self, root: Root, runner: Runner, sleep: Callable[[float], None], out):
        self.root, self.runner, self.sleep, self.out = root, runner, sleep, out
        self.masked = False

    def stop(self) -> None:
        if not self.root.is_live:
            print("--root: leaving this system's fprintd alone", file=self.out)
            return
        if self.runner(["systemctl", "mask", "--runtime", "--now", self.UNIT], None) != 0:
            raise Refusal("could not stop fprintd (systemctl mask --runtime --now "
                          "fprintd.service); nothing was changed")
        self.masked = True
        # A verify already running finishes its save within about a second.
        self.sleep(3)

    def release(self) -> None:
        if self.masked:
            self.runner(["systemctl", "unmask", "--runtime", self.UNIT], None)
            self.masked = False

    def open_sensor(self) -> None:
        """Touch ID activation (and the keybag load) runs at the first open of
        the sensor; fprintd-list opens it."""
        if self.root.is_live:
            self.runner(["fprintd-list", "root"], 20)


def say(out, text: str = "") -> None:
    print(text, file=out or sys.stdout)


def tree_files(path: Path) -> list[Path]:
    if path.is_dir() and not path.is_symlink():
        return sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink())
    return [path]
