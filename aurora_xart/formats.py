# SPDX-License-Identifier: MIT
"""Decoders for the apple_sep driver's host files.

Each format follows the driver source in aurora-silicon/linux at
KERNEL_COMMIT; docs/FORMATS.md cites the file and function for every field.
Decoding never returns key material: wrapped bags, secrets and saved record
values are measured, not kept.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

KERNEL_COMMIT = "a20af80f9233e3be2e74fd52e22b56c8e583b5a6"


def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE, as store.rs computes it."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def crc32_ieee(data: bytes) -> int:
    """CRC-32/ISO-HDLC, as xart_store.rs computes it."""
    return zlib.crc32(data) & 0xFFFFFFFF


# ---- the identity keybag slot (keybag.rs) ----------------------------------

KEYBAG_MAGIC = b"APPLE-SEP-KBAG01"
KEYBAG_VERSION = 2
STATE_INTENT = 0
STATE_COMMITTED = 1
STATE_REFUSED = 2
STATE_COMMITTED_BAG_UUID = 3
OFF_VERSION = 0x10
OFF_STATE = 0x14
OFF_LEN = 0x18
OFF_CRC = 0x1C
OFF_UUID = 0x20
OFF_SECRET_LEN = 0x30
KEYBAG_HEADER = 0x34
UUID_LEN = 16
MAX_WRAPPED = 0x8000
MARK_MAGIC = b"AXGI"


@dataclass(frozen=True)
class Unfinished:
    """What an intent recorded about Linux's list (xart_guard.rs `Unfinished`)."""

    kind: str  # "unmarked", "unguarded" or "guarded"
    entries: int = 0

    def __str__(self) -> str:
        # As the kernel log prints it.
        if self.kind == "guarded":
            return f"Guarded({self.entries})"
        return self.kind.capitalize()

    def describe(self) -> str:
        if self.kind == "guarded":
            n = self.entries
            if n == 0:
                return "sent under the xART guard while Linux's list was empty"
            entries = "entry" if n == 1 else "entries"
            return f"sent under the xART guard with {n} {entries} in Linux's list"
        if self.kind == "unguarded":
            return "sent with no xART guard running"
        return "written by a driver that did not record Linux's list"


def may_retry_create(unfinished: Unfinished, listed: int | None) -> bool:
    """xart_guard.rs `may_retry_create`: may an unfinished create be sent again?"""
    if listed is None:
        return False
    if unfinished.kind == "guarded":
        return listed == unfinished.entries
    if unfinished.kind == "unmarked":
        return listed == 0
    return False


def keybag_checksum_input(state: int, wrapped: bytes, uuid: bytes, secret: bytes) -> bytes:
    return (
        struct.pack("<IIII", KEYBAG_VERSION, state, len(wrapped), len(secret))
        + uuid
        + wrapped
        + secret
    )


def encode_mark(unfinished: Unfinished) -> bytes:
    if unfinished.kind == "unmarked":
        return bytes(UUID_LEN)
    guarded = 1 if unfinished.kind == "guarded" else 0
    entries = unfinished.entries if guarded else 0
    return MARK_MAGIC + bytes([guarded, 0, 0, 0]) + struct.pack("<Q", entries)


def decode_mark(uuid: bytes) -> Unfinished | None:
    if uuid == bytes(UUID_LEN):
        return Unfinished("unmarked")
    if uuid[:4] != MARK_MAGIC or uuid[5:8] != bytes(3):
        return None
    entries = struct.unpack("<Q", uuid[8:16])[0]
    if uuid[4] == 0 and entries == 0:
        return Unfinished("unguarded")
    if uuid[4] == 1:
        return Unfinished("guarded", entries)
    return None


def keybag_record(state: int, wrapped: bytes = b"", uuid: bytes = bytes(UUID_LEN),
                  secret: bytes = b"") -> bytes:
    """A slot file as keybag.rs `write_record` lays it out."""
    crc = crc16_ccitt_false(keybag_checksum_input(state, wrapped, uuid, secret))
    head = (
        KEYBAG_MAGIC
        + struct.pack("<IIIH2x", KEYBAG_VERSION, state, len(wrapped), crc)
        + uuid
        + struct.pack("<I", len(secret))
    )
    assert len(head) == KEYBAG_HEADER
    return head + wrapped + secret


STATE_NAMES = {
    STATE_INTENT: "intent",
    STATE_COMMITTED: "committed",
    STATE_REFUSED: "refused",
    STATE_COMMITTED_BAG_UUID: "committed",
}


@dataclass
class KeybagSlot:
    """The slot file as the driver reads it at probe."""

    size: int
    # What keybag.rs `read` returns: "present", "absent" or an errno name.
    driver_read: str
    state: int | None = None
    state_name: str = "damaged"
    provenance: str | None = None  # "host-generated" or "read back from the bag"
    uuid: bytes | None = None
    wrapped_len: int | None = None
    secret_len: int | None = None
    # For an intent: the mark, or None when keybag.rs `unfinished` fails.
    intent: Unfinished | None = None
    intent_error: str | None = None
    problem: str | None = None


def _word(head: bytes, off: int) -> int:
    return struct.unpack_from("<I", head, off)[0]


def _decode_intent(data: bytes) -> tuple[Unfinished | None, str | None]:
    """keybag.rs `unfinished`: the mark of one intact intent, or an errno name."""
    if len(data) != KEYBAG_HEADER:
        return None, "EINVAL"
    head = data
    if head[: len(KEYBAG_MAGIC)] != KEYBAG_MAGIC:
        return None, "EINVAL"
    if _word(head, OFF_VERSION) != KEYBAG_VERSION:
        return None, "ENOTSYNC"
    if (_word(head, OFF_STATE) != STATE_INTENT or _word(head, OFF_LEN) != 0
            or _word(head, OFF_SECRET_LEN) != 0):
        return None, "EEXIST"
    uuid = head[OFF_UUID:OFF_UUID + UUID_LEN]
    crc = struct.unpack_from("<H", head, OFF_CRC)[0]
    if (head[OFF_CRC + 2:OFF_CRC + 4] != bytes(2)
            or crc16_ccitt_false(keybag_checksum_input(STATE_INTENT, b"", uuid, b"")) != crc):
        return None, "EINVAL"
    mark = decode_mark(uuid)
    if mark is None:
        return None, "EEXIST"
    return mark, None


def decode_keybag(data: bytes) -> KeybagSlot:
    """Follows keybag.rs `read`, then `unfinished` for an intent."""
    size = len(data)
    if size < KEYBAG_HEADER:
        return KeybagSlot(size, "EINVAL", problem=f"shorter ({size} bytes) than its header")
    head = data[:KEYBAG_HEADER]
    if head[: len(KEYBAG_MAGIC)] != KEYBAG_MAGIC:
        return KeybagSlot(size, "EINVAL", problem="not a keybag slot (wrong magic)")
    version = _word(head, OFF_VERSION)
    if version != KEYBAG_VERSION:
        return KeybagSlot(size, "ENOTSYNC", state_name="old-version",
                          problem=f"format version {version}, which this driver refuses")
    state = _word(head, OFF_STATE)
    slot = KeybagSlot(size, "EINVAL", state=state)
    if state == STATE_REFUSED:
        slot.driver_read = "absent"
        slot.state_name = "refused"
        return slot
    if state not in (STATE_COMMITTED, STATE_COMMITTED_BAG_UUID):
        # An intent, or a state no driver writes: a bag may exist unnamed.
        slot.driver_read = "EEXIST"
        slot.state_name = "intent" if state == STATE_INTENT else "unknown"
        slot.intent, slot.intent_error = _decode_intent(data)
        if state != STATE_INTENT:
            slot.problem = f"unknown state {state}"
        elif slot.intent_error == "EINVAL":
            slot.problem = "the intent record is damaged (size or checksum)"
        elif slot.intent_error == "EEXIST":
            slot.problem = "the intent carries a mark no driver writes"
        return slot
    slot.state_name = "committed"
    slot.provenance = "host-generated" if state == STATE_COMMITTED else "read back from the bag"
    wrapped_len = _word(head, OFF_LEN)
    secret_len = _word(head, OFF_SECRET_LEN)
    slot.wrapped_len, slot.secret_len = wrapped_len, secret_len
    slot.uuid = head[OFF_UUID:OFF_UUID + UUID_LEN]
    if wrapped_len == 0 or wrapped_len > MAX_WRAPPED or size < KEYBAG_HEADER + wrapped_len:
        slot.problem = "the wrapped bag's length is out of range or truncated"
        slot.state_name = "damaged"
        return slot
    if secret_len > MAX_WRAPPED or size < KEYBAG_HEADER + wrapped_len + secret_len:
        slot.problem = "the secret's length is out of range or truncated"
        slot.state_name = "damaged"
        return slot
    if size != KEYBAG_HEADER + wrapped_len + secret_len:
        slot.problem = "trailing bytes after the record"
        slot.state_name = "damaged"
        return slot
    wrapped = data[KEYBAG_HEADER:KEYBAG_HEADER + wrapped_len]
    secret = data[KEYBAG_HEADER + wrapped_len:]
    crc = struct.unpack_from("<H", head, OFF_CRC)[0]
    if crc16_ccitt_false(keybag_checksum_input(state, wrapped, slot.uuid, secret)) != crc:
        slot.problem = "checksum mismatch (a torn write or damage)"
        slot.state_name = "damaged"
        return slot
    slot.driver_read = "present"
    return slot


# ---- Linux's list of its own xART records (xart_guard.rs) ------------------

ENTRY_SIZE = 32
ENTRY_MAGIC = b"AXGO"
ALLOW_MAGIC = b"AXGA"
PREVIOUS_MAGIC = b"AXGP"
MAX_ENTRIES = 4096


def encode_entry(kind: int, uuid: bytes, magic: bytes = ENTRY_MAGIC) -> bytes:
    """xart_guard.rs `encode_with`."""
    entry = bytearray(ENTRY_SIZE)
    entry[:4] = magic
    entry[4] = kind
    entry[8:24] = uuid
    entry[24:28] = struct.pack("<I", crc32_ieee(bytes(entry[:24])))
    return bytes(entry)


def decode_entry(entry: bytes, magic: bytes = ENTRY_MAGIC) -> tuple[int, bytes] | None:
    """xart_guard.rs `decode_with`: (kind, session id), or None if torn or foreign."""
    if len(entry) != ENTRY_SIZE or entry[:4] != magic or entry[5:8] != bytes(3):
        return None
    crc = struct.unpack_from("<I", entry, 24)[0]
    if crc != crc32_ieee(entry[:24]) or entry[4] not in (3, 4):
        return None
    return entry[4], bytes(entry[8:24])


@dataclass
class ListEntry:
    index: int
    kind: int | None  # None for a torn entry
    session: str | None
    repeated: bool = False


@dataclass
class GuardList:
    size: int
    entries: list[ListEntry] = field(default_factory=list)
    # Whole 32-byte entries, torn and repeated ones included: what the driver
    # counts as the list's length (`loaded_entries`).
    whole: int = 0
    tail_bytes: int = 0
    too_long: bool = False

    @property
    def records(self) -> list[ListEntry]:
        return [e for e in self.entries if e.kind is not None and not e.repeated]

    @property
    def torn(self) -> int:
        return sum(1 for e in self.entries if e.kind is None)

    @property
    def repeated(self) -> int:
        return sum(1 for e in self.entries if e.repeated)

    @property
    def driver_count(self) -> int | None:
        """The length the guard loads, or None when it refuses the list."""
        return None if self.too_long else self.whole


def decode_list(data: bytes) -> GuardList:
    """Follows xart_guard.rs `Guard::load`."""
    size = len(data)
    whole = size // ENTRY_SIZE
    result = GuardList(size, whole=whole, tail_bytes=size % ENTRY_SIZE)
    if whole > MAX_ENTRIES:
        result.too_long = True
    seen = set()
    for i in range(min(whole, MAX_ENTRIES)):
        decoded = decode_entry(data[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE])
        if decoded is None:
            result.entries.append(ListEntry(i, None, None))
            continue
        kind, uuid = decoded
        result.entries.append(ListEntry(i, kind, uuid.hex(), repeated=decoded in seen))
        seen.add(decoded)
    return result


@dataclass
class Allowance:
    kind: int
    session: str | None  # None: the first existing record of this kind

    def describe(self) -> str:
        if self.session is None:
            return f"the first existing kind-{self.kind} record the enclave asks to rewrite"
        return f"kind-{self.kind} record {self.session}"


def decode_allowance(data: bytes) -> tuple[Allowance | None, str | None]:
    """xart_guard.rs `take_allowance`: (allowance, problem). Empty means none."""
    if not data:
        return None, None
    if len(data) != ENTRY_SIZE:
        return None, f"{len(data)} bytes, not one {ENTRY_SIZE}-byte entry; the driver ignores it"
    decoded = decode_entry(data, ALLOW_MAGIC)
    if decoded is None:
        return None, "damaged; the driver ignores it"
    kind, uuid = decoded
    return Allowance(kind, None if uuid == bytes(16) else uuid.hex()), None


@dataclass
class PreviousValue:
    kind: int
    session: str
    length: int
    crc_ok: bool


def previous_record(kind: int, uuid: bytes, value: bytes) -> bytes:
    """xart_guard.rs `save_previous`: one appended record."""
    head = bytearray(32)
    head[:4] = PREVIOUS_MAGIC
    head[4] = kind
    head[8:24] = uuid
    head[24:28] = struct.pack("<I", len(value))
    head[28:32] = struct.pack("<I", crc32_ieee(value))
    return bytes(head) + value


def decode_previous(data: bytes) -> tuple[list[PreviousValue], int]:
    """The saved previous values, without the values, and any bytes left over."""
    records = []
    off = 0
    while off + 32 <= len(data):
        head = data[off:off + 32]
        if head[:4] != PREVIOUS_MAGIC:
            break
        length = struct.unpack_from("<I", head, 24)[0]
        if off + 32 + length > len(data):
            break
        value = data[off + 32:off + 32 + length]
        crc = struct.unpack_from("<I", head, 28)[0]
        records.append(PreviousValue(head[4], bytes(head[8:24]).hex(), length,
                                     crc == crc32_ieee(value)))
        off += 32 + length
    return records, len(data) - off


# ---- the Touch ID lockout record (sbio.rs) ---------------------------------

LOCKOUT_MAGIC = b"SEPLOCK1"
LOCKOUT_RECORD_LEN = 16


def lockout_record(locked: bool) -> bytes:
    return LOCKOUT_MAGIC + struct.pack("<I", 1 if locked else 0) + bytes(4)


def lockout_locked(data: bytes) -> bool:
    """sbio.rs `read_lockout_record`: anything but one locked record is no lockout."""
    return (len(data) == LOCKOUT_RECORD_LEN and data[:8] == LOCKOUT_MAGIC
            and struct.unpack_from("<I", data, 8)[0] == 1)
