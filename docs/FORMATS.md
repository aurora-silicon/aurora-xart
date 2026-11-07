# The driver's host files and diagnostics

Everything aurora-xart reads is defined by the `apple_sep` driver in
[aurora-silicon/linux](https://github.com/aurora-silicon/linux), branch
`integration/aurora`, at commit
[`a20af80f9233e3be2e74fd52e22b56c8e583b5a6`](https://github.com/aurora-silicon/linux/tree/a20af80f9233e3be2e74fd52e22b56c8e583b5a6)
(2026-11-07). The file references below are to that commit, under
`drivers/soc/apple/` unless they say otherwise; `aurora_xart/formats.py` names
the same constants. Integers are little-endian.

When the driver changes one of these formats, change `formats.py`, its tests
and this page together, and move the commit here and in
`formats.KERNEL_COMMIT`.

## The identity keybag slot: `/var/lib/aurora-sep-keybag.bin`

`keybag.rs`: `KEYBAG_PATH` (line 15), the layout constants (lines 30-72),
`checksum_input` (130), `read` (149), `decode_mark` (261), `decode_intent`
(284), `unfinished` (308) and `write_record` (399).

| Offset | Size | Field |
| --- | --- | --- |
| 0x00 | 16 | magic `APPLE-SEP-KBAG01` |
| 0x10 | 4 | version, 2 (a version 1 record is refused: `ENOTSYNC`) |
| 0x14 | 4 | state |
| 0x18 | 4 | length of the wrapped bag |
| 0x1c | 2 | CRC-16/CCITT-FALSE of the checksum input; two zero bytes follow |
| 0x20 | 16 | UUID field |
| 0x30 | 4 | length of the bag secret |
| 0x34 | | the wrapped bag, then the secret |

The checksum input is version, state, wrapped length and secret length (four
32-bit words), then the UUID field, the wrapped bag and the secret. The CRC is
`crc16_ccitt_false` in `store.rs` (line 430): polynomial 0x1021, initial value
0xFFFF, not reflected; the check value of `123456789` is 0x29B1.

States:

| State | Name | Meaning |
| --- | --- | --- |
| 0 | intent | Written before CREATE_KEYBAG is sent. Until it is replaced a bag may exist that nothing names, so `read` returns `EEXIST` and the driver creates no other bag. |
| 1 | committed | The UUID field is the host-generated UUID the bag was created with. |
| 2 | refused | The enclave refused the create: nothing exists, so `read` reports no bag and the next boot tries again. Neither length nor checksum is looked at. |
| 3 | committed | The UUID field is the bag's own, read back from the enclave. |

Any other state reads as an intent. A committed record is refused (`EINVAL`)
when either length is zero or above 0x8000 (`store::MAX_VALUE`, line 15), when
the file is not exactly header plus both bodies, or when the checksum does not
match.

An intent's UUID field records Linux's xART guard list when the create was
sent (`encode_mark`, line 248): `AXGI`, then 1 if a guard ran or 0 if not,
three zero bytes, and the list's entry count as a 64-bit integer. Drivers that
predate the mark left the field zero.

| UUID field | Intent (`Unfinished`, `xart_guard.rs`) |
| --- | --- |
| all zero | `Unmarked`: an older driver |
| `AXGI` 00 000000, count 0 | `Unguarded`: no guard ran |
| `AXGI` 01 000000, count n | `Guarded(n)`: the list had n entries |

`unfinished` decodes an intent only if the file is exactly 0x34 bytes, both
lengths are zero, the padding is zero and the checksum matches; otherwise the
intent cannot be judged and stays ambiguous.

### When the driver sends an unfinished create again

`sks.rs` `sks_retry_unfinished_create` (line 635) asks
`xart_guard.rs` `may_retry_create` (line 153), passing the length of Linux's
list as the guard loaded it this boot (`None` when no guard runs or the list
could not be loaded):

| Intent | List now | Sent again? |
| --- | --- | --- |
| any | none (no guard, or no list) | no |
| `Guarded(n)` | n | yes |
| `Guarded(n)` | not n | no: the list grew (a record may exist) or was rolled back |
| `Unmarked` | 0 | yes |
| `Unmarked` | more than 0 | no |
| `Unguarded` | any | no |

When it is not sent again the driver logs "an earlier CREATE_KEYBAG never
completed and may have left a bag (intent ..., xART guard list ...)", then
"identity keybag state is ambiguous: EEXIST", and the boot's bring-up stops
there. This is the stuck M1 case: an older kernel guarded M1 Macs and wrote
`Guarded(0)`; since linux#1049 the M1 profiles default to `xart_guard` 0, so
the list is `None` and the intent is never sent again.

## Linux's list of its own xART records: `/var/lib/aurora-sep-xart-owned.bin`

`xart_guard.rs`: `OWNED_PATH` (line 66), `ENTRY_SIZE` and the magics
(186-188), `MAX_ENTRIES` (193), `encode_with` (281), `decode_with` (296) and
`Guard::load` (521).

A sequence of 32-byte entries, appended before each new session record is
written:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `AXGO` |
| 4 | 1 | record kind, 3 or 4 (the shared roots, kinds 1 and 2, are never listed) |
| 5 | 3 | zero |
| 8 | 16 | session id |
| 24 | 4 | CRC-32/ISO-HDLC of bytes 0-23 |
| 28 | 4 | not checked |

The CRC is `crc32_ieee` in `xart_store.rs` (line 505), the zlib CRC-32. An
entry with the wrong magic, kind, padding or CRC is torn and ignored. The
list's length, which `may_retry_create` compares, is the number of whole
32-byte entries, torn and repeated ones included; bytes past the last whole
entry are a torn append, not counted and overwritten by the next one. A file
of more than 4096 whole entries is refused, and the guard then runs without a
list (every session write is refused). The entries hold no key material.

## The one-time allowance: `/var/lib/aurora-sep-xart-allow-once.bin`

`xart_guard.rs` `ALLOW_PATH` (line 68), `Allowance::decode` (337) and
`take_allowance` (356). Empty, or one 32-byte entry laid out as a list entry
with magic `AXGA`. An all-zero session id allows the first existing record of
that kind the enclave asks to rewrite; another id names the record. The
driver empties the file at probe before it uses the allowance, and ignores a
file of any other size or a damaged entry.

## Saved previous values: `/var/lib/aurora-sep-xart-policy-previous.bin`

`xart_guard.rs` `PREVIOUS_PATH` (line 71) and `save_previous` (170). Appended
records, each a 32-byte header and the value:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | magic `AXGP` |
| 4 | 1 | record kind |
| 8 | 16 | session id |
| 24 | 4 | value length |
| 28 | 4 | CRC-32 of the value |

aurora-xart shows the kind, session id and length, and whether the CRC
matches, never the value.

## The Touch ID lockout record: `/var/lib/aurora-sep-touchid-lockout.bin`

`sbio.rs` lines 22-25 and `lockout_record` (60): 16 bytes, `SEPLOCK1`, then 1
as a 32-bit integer while Touch ID is locked after failed matches. Anything
else reads as not locked. A password authentication clears it.

## The other state files

Read only for their presence, size and time:

| File | Source |
| --- | --- |
| `/var/lib/aurora-sep-host-state.bin` | `store.rs` `STORE_PATH` (line 9) |
| `/var/lib/apple-sep-catacomb-{master,owner,user}.bin` | `catacomb.rs` `path_for` (line 18) |
| `/var/lib/aurora-sep-refkey.bin`, `-refkey-v2.bin` | `refkey.rs` lines 170-171 |

`reset-touchid` moves the files `tools/aurora-sep/install-aurora-sep.sh` lists
in `TOUCHID_STATE_FILES` (line 4659), keybag last, and each user's
`/var/lib/fprint/<user>/apple-sep`, as `reset_touchid` (line 4677) does. It
keeps the guard's three files, the lockout record and the calibration.

## Module parameters

`sep.rs` `module!` (line 3016): `xart_writes` (u8, default 1),
`provision_keybag` (u8, default 1; probe refuses it without `xart_writes`,
line 2906) and `xart_guard` (i8, default -1). The driver does not expose them
in sysfs, so aurora-xart reads them as configured: modprobe.d's `options
apple_sep` lines in kmod's order, then `apple_sep.<name>=` on the kernel
command line, which kmod passes after them, so the last value wins. A value
in `/sys/module/apple_sep/parameters/` replaces both, should a driver expose
one.

`xart_guard` -1 takes the profile's level (`xart_guard.rs` `level`, line 228;
`profile.rs`): 0 on T8103/J313, T6000/J316s (M1 family) and T8140/J700
(MacBook Neo), 1 on T6020 (M2 Pro/Max), T8112 (M2), T8122 (M3), T6040/T6041
(M4 Pro/Max) and T8132 (M4). `profile.rs` `select` (line 617) picks the
profile from the root `compatible` list. A level above 2 counts as 2. No
guard runs while xART writes are disabled.

A read-only install (`install-aurora-sep.sh --read-only`, `sep_policy`, line 3662)
writes `options apple_sep xart_writes=0 provision_keybag=0` to
`/etc/modprobe.d/aurora-sep.conf` (`MODPROBE_CONF`, line 301). The installer's
`--reset-touchid` refuses whenever that file exists; owners also use the file
to turn writes on, so aurora-xart refuses only when it, or the configuration
as a whole, turns either parameter off.

## The driver's diagnostics

`diag_shim.c` and `Documentation/ABI/testing/sysfs-driver-apple-sep`:
`/sys/bus/platform/devices/<unit>.sep/diag/`, one token per attribute, ABI 2.
aurora-xart reads every attribute there and uses `keybag` (`present`,
`missing`, `failed`, `unknown`), `touchid`, `xart` (`enabled`, `disabled`),
`xart_guard` (the effective level), `xart_guard_list` (`none`, `loaded`,
`unavailable`), `xart_guard_refusals` and `matching`. The guard attributes are
newer than ABI 2 itself, so their absence is not an error. `keybag` reads
`failed` when the bring-up could not provision the keybag (`sbio.rs`, line
1879), which is what the stuck intent causes.
