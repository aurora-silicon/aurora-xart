# aurora-xart

Inspect and manage the Linux side of the Secure Enclave and xART state on
Aurora Linux for Apple silicon Macs, in the spirit of `xartutil` on macOS.

The Secure Enclave keeps its anti-replay state in xART, a store on the iBoot
system container that every OS on the Mac shares. Linux's `apple_sep` driver
keeps Linux's own state in `/var/lib`: the Touch ID identity keybag slot, the
catacombs, the machine ref-key, and the xART guard's list of the session
records the enclave created while Linux ran. aurora-xart reads that state and
the driver's diagnostics, says in plain words what is wrong and what to do,
and can move the Touch ID state aside to start Touch ID over.

    aurora-xart status            # what the driver and its files say, and what to do
    aurora-xart list              # Linux's xART records and the state files
    sudo aurora-xart reset-touchid

`status` and `list` take `--json`. `man aurora-xart` and `aurora-xart --help`
describe every command and option.

## Why it exists

Kernels before aurora-silicon/linux#1049 ran the xART guard on M1 Macs. If
Touch ID setup on such a kernel never finished, the driver left an intent in
the keybag slot that records the guard's list ("Guarded(0)"). The current
kernel runs M1 Macs without the guard (`xart_guard` defaults to 0 on
T8103/T600x), so it has no list to prove the intent left no bag, and it
refuses to create a keybag on every boot:

```
apple_sep 242400000.sep: sks: an earlier CREATE_KEYBAG never completed and may have left a bag (intent Guarded(0), xART guard list None); not creating another
apple_sep 242400000.sep: sks: identity keybag state is ambiguous: EEXIST
apple_sep 242400000.sep: bringup: identity-keybag provisioning failed; no retry this boot
```

`aurora-xart status` names that state and the fix:

```
Keybag slot  intent: an unfinished create, sent under the xART guard while Linux's list was empty
             (Guarded(0); the driver will not send it again)
Guard list   0 records (0 bytes)

PROBLEM: An earlier keybag create never finished, and the driver cannot prove
  it left no bag: it was sent under the xART guard while Linux's list was
  empty, but this kernel runs the Mac without the guard (xart_guard defaults to
  0 on M1 Macs since linux#1049), so it has no list to check the create
  against. ...
  -> Run `sudo aurora-xart reset-touchid` to start Touch ID over.
```

The fix used to be `install-aurora-sep.sh --reset-touchid`, which the
distributions do not ship. `aurora-xart reset-touchid` does the same, with
the same safety checks, and it is packaged with aurora-sep on Fedora, ALARM
and NixOS.

## Commands

**`status`** shows the platform and its SEP profile, the driver's diagnostics
from `/sys/bus/platform/devices/*.sep/diag`, the effective xART guard level,
the module parameters and where each value comes from, whether the install
is read-only, the keybag slot and the guard list, and then explains anything
stuck. Without root it shows what sysfs and the configuration show and says
which files need root.

**`list`** lists the records on Linux's guard list (kind and session id, no
key material), torn and repeated entries, the one-time allowance, the saved
previous values (kind, session id and length, never the value), the keybag
slot with its state and provenance, and which state files, prints and
calibration files exist.

**`reset-touchid [--yes] [--force]`** starts Touch ID over:

- it refuses on a read-only install, when the driver is not running, when
  xART writes are disabled this boot, and when the keybag works unless
  `--force` (if Touch ID has not been activated this boot it opens the sensor
  once through `fprintd-list` first, since only that loads the keybag);
- it says what is lost and asks you to type RESET unless `--yes`;
- it masks fprintd until the next boot, so no match or enrolment writes state
  behind it;
- it moves each user's `/var/lib/fprint/<user>/apple-sep` and the Touch ID
  state files, the keybag last, into a new
  `/var/lib/aurora-sep-touchid-reset-<time>/`, and if a move fails it puts
  back everything already moved;
- it keeps `aurora-sep-xart-owned.bin` and the guard's other files, the Touch
  ID calibration and the lockout record.

Then reboot: the driver creates a new keybag during boot, and every finger is
enrolled again. The old bag, if the enclave kept one, stays there unused.

`--root DIR` runs any command against the files under `DIR`, laid out as on
a Mac (`proc/device-tree`, `sys`, `etc`, `var/lib`), instead of this system,
and leaves this system's services alone. The tests use it.

Exit status: 0 when nothing is wrong or the command did what it was asked, 1
when `status` or `list` found a problem that needs action, 2 when a command
refused.

## What it never does

aurora-xart never talks to the Secure Enclave, never writes xART and never
deletes a file. Its only change is `reset-touchid` renaming Linux's own files
in `/var/lib`.

It has no backup or restore. The enclave's state is anti-replay protected:
the keybag, catacombs and ref-key on disk only match the enclave as it is now,
so a saved copy of them cannot be put back into use.

`xartutil` on macOS can also erase xART: one session record, or all of them
(`xartutil --erase-all`). aurora-xart has no such option, and won't:

- every OS on the Mac shares xART, and nothing in a record says which OS
  wrote it, so erasing from Linux could destroy macOS's (or another Linux
  install's) Touch ID and anti-replay state;
- the enclave's anti-replay counters cannot be rolled back, so a record
  erased or written back from Linux may never be accepted again;
- only the enclave writes xART, through the driver, which keeps those writes
  to the records Linux created (the xART guard).

To start over on the Linux side, `reset-touchid` moves Linux's files aside and
lets the driver create a new keybag. Erasing xART itself is for macOS's own
tools, or a DFU restore.

## Install

The packages are `aurora-xart` on Aurora Fedora and Aurora ALARM, and
`pkgs.aurora-xart` on Aurora NixOS; aurora-sep pulls them in. From a
checkout:

    make check                    # unit tests (Python 3.11 or later, no dependencies)
    make lint                     # ruff
    sudo make install PREFIX=/usr # /usr/bin/aurora-xart, the package in /usr/share/aurora-xart

## Formats

[docs/FORMATS.md](docs/FORMATS.md) describes every file and attribute
aurora-xart reads, with the driver source it follows: aurora-silicon/linux
`integration/aurora` at
[`a20af80f9233`](https://github.com/aurora-silicon/linux/tree/a20af80f9233e3be2e74fd52e22b56c8e583b5a6).
The tests build synthetic state files from those formats.

## Licence

MIT, as the other Aurora userspace tools (aurora-diag, aurora-bless). See
[LICENSE](LICENSE).
