# SPDX-License-Identifier: MIT
"""The decoders against the driver's own rules and KUnit cases."""

import unittest

import fakemac  # noqa: F401  (puts the package on the path)
from aurora_xart import formats as f
from aurora_xart.formats import Unfinished


class Checksums(unittest.TestCase):
    def test_check_values(self):
        # store.rs and xart_store.rs assert the same values at build time.
        self.assertEqual(f.crc16_ccitt_false(b"123456789"), 0x29B1)
        self.assertEqual(f.crc32_ieee(b"123456789"), 0xCBF43926)


class Keybag(unittest.TestCase):
    MARKS = [Unfinished("unmarked"), Unfinished("unguarded"), Unfinished("guarded", 0),
             Unfinished("guarded", 7), Unfinished("guarded", 2**64 - 1)]

    def intent(self, unfinished):
        return f.keybag_record(f.STATE_INTENT, uuid=f.encode_mark(unfinished))

    def test_layout_matches_the_driver(self):
        head = f.keybag_record(f.STATE_COMMITTED, b"\x01\x02", b"\x03" * 16, b"\x04")
        self.assertEqual(head[:16], b"APPLE-SEP-KBAG01")
        self.assertEqual(head[0x10:0x14], (2).to_bytes(4, "little"))
        self.assertEqual(head[0x14:0x18], (1).to_bytes(4, "little"))
        self.assertEqual(head[0x18:0x1C], (2).to_bytes(4, "little"))
        self.assertEqual(head[0x1E:0x20], b"\0\0")
        self.assertEqual(head[0x20:0x30], b"\x03" * 16)
        self.assertEqual(head[0x30:0x34], (1).to_bytes(4, "little"))
        self.assertEqual(head[0x34:], b"\x01\x02\x04")

    def test_intents_round_trip(self):
        for mark in self.MARKS:
            slot = f.decode_keybag(self.intent(mark))
            self.assertEqual(slot.driver_read, "EEXIST")
            self.assertEqual(slot.state_name, "intent")
            self.assertEqual(slot.intent, mark)
            self.assertIsNone(slot.intent_error)

    def test_the_kernel_log_spelling(self):
        self.assertEqual(str(Unfinished("guarded", 0)), "Guarded(0)")
        self.assertEqual(str(Unfinished("unmarked")), "Unmarked")
        self.assertEqual(str(Unfinished("unguarded")), "Unguarded")

    def test_an_earlier_drivers_intent_is_unmarked(self):
        slot = f.decode_keybag(f.keybag_record(f.STATE_INTENT))
        self.assertEqual(slot.intent, Unfinished("unmarked"))

    def test_damaged_or_foreign_intents_stay_ambiguous(self):
        good = bytearray(self.intent(Unfinished("guarded", 3)))
        flipped = bytearray(good)
        flipped[f.OFF_UUID + 8] ^= 1
        slot = f.decode_keybag(bytes(flipped))
        self.assertEqual((slot.driver_read, slot.intent, slot.intent_error),
                         ("EEXIST", None, "EINVAL"))
        other = bytes([1]) + bytes(15)
        slot = f.decode_keybag(f.keybag_record(f.STATE_INTENT, uuid=other))
        self.assertEqual((slot.intent, slot.intent_error), (None, "EEXIST"))
        odd = bytearray(f.encode_mark(Unfinished("unguarded")))
        odd[8] = 1
        slot = f.decode_keybag(f.keybag_record(f.STATE_INTENT, uuid=bytes(odd)))
        self.assertEqual((slot.intent, slot.intent_error), (None, "EEXIST"))
        magic = bytearray(good)
        magic[0] ^= 1
        self.assertEqual(f.decode_keybag(bytes(magic)).driver_read, "EINVAL")
        version = bytearray(good)
        version[f.OFF_VERSION] = 1
        self.assertEqual(f.decode_keybag(bytes(version)).driver_read, "ENOTSYNC")

    def test_an_intent_with_trailing_bytes_cannot_be_judged(self):
        slot = f.decode_keybag(self.intent(Unfinished("guarded", 0)) + b"\0")
        self.assertEqual((slot.driver_read, slot.intent_error), ("EEXIST", "EINVAL"))

    def test_committed_records(self):
        for state, provenance in ((f.STATE_COMMITTED, "host-generated"),
                                  (f.STATE_COMMITTED_BAG_UUID, "read back from the bag")):
            slot = f.decode_keybag(f.keybag_record(state, b"w" * 100, b"u" * 16, b"s" * 32))
            self.assertEqual(slot.driver_read, "present")
            self.assertEqual(slot.provenance, provenance)
            self.assertEqual((slot.wrapped_len, slot.secret_len), (100, 32))

    def test_damaged_committed_records(self):
        good = f.keybag_record(f.STATE_COMMITTED, b"w" * 100, b"u" * 16, b"s" * 32)
        cases = {
            "torn body": good[:-1] + bytes([good[-1] ^ 1]),
            "truncated": good[:-5],
            "trailing": good + b"x",
            "empty bag": f.keybag_record(f.STATE_COMMITTED, b"", b"u" * 16, b""),
            "short": good[:20],
        }
        for name, data in cases.items():
            with self.subTest(name):
                slot = f.decode_keybag(data)
                self.assertEqual(slot.driver_read, "EINVAL")
                self.assertTrue(slot.problem)

    def test_a_refusal_reads_as_no_bag(self):
        refused = bytearray(f.keybag_record(f.STATE_REFUSED))
        # keybag.rs `read` returns Absent before it looks at the checksum.
        refused[f.OFF_CRC] ^= 0xFF
        slot = f.decode_keybag(bytes(refused))
        self.assertEqual((slot.driver_read, slot.state_name), ("absent", "refused"))

    def test_an_unknown_state_is_treated_as_an_intent(self):
        slot = f.decode_keybag(f.keybag_record(9))
        self.assertEqual((slot.driver_read, slot.state_name), ("EEXIST", "unknown"))

    def test_may_retry_create_matches_the_driver(self):
        G, U, N = (lambda n: Unfinished("guarded", n)), Unfinished("unmarked"), \
            Unfinished("unguarded")
        self.assertTrue(f.may_retry_create(G(0), 0))
        self.assertTrue(f.may_retry_create(G(3), 3))
        self.assertFalse(f.may_retry_create(G(3), 4))
        self.assertFalse(f.may_retry_create(G(3), 2))
        self.assertFalse(f.may_retry_create(G(3), None))
        self.assertFalse(f.may_retry_create(U, None))
        self.assertFalse(f.may_retry_create(N, 0))
        self.assertFalse(f.may_retry_create(N, None))
        self.assertTrue(f.may_retry_create(U, 0))
        self.assertFalse(f.may_retry_create(U, 1))


class GuardList(unittest.TestCase):
    def test_entries_round_trip(self):
        entry = f.encode_entry(3, b"\x5a" * 16)
        self.assertEqual(len(entry), 32)
        self.assertEqual(entry[:4], b"AXGO")
        self.assertEqual(f.decode_entry(entry), (3, b"\x5a" * 16))

    def test_damaged_entries_are_ignored(self):
        entry = bytearray(f.encode_entry(4, b"\x07" * 16))
        entry[9] ^= 1
        self.assertIsNone(f.decode_entry(bytes(entry)))
        # A shared root is never listed.
        self.assertIsNone(f.decode_entry(f.encode_entry(1, bytes(16))))
        self.assertIsNone(f.decode_entry(f.encode_entry(4, b"\x07" * 16)[:31]))

    def test_the_length_counts_torn_entries_but_not_a_torn_tail(self):
        good = f.encode_entry(4, b"\x04" * 16)
        torn = bytearray(f.encode_entry(4, b"\x05" * 16))
        torn[12] ^= 1
        data = good + bytes(torn) + good + f.encode_entry(4, b"\x06" * 16)[:10]
        gl = f.decode_list(data)
        self.assertEqual((gl.whole, gl.torn, gl.repeated, gl.tail_bytes), (3, 1, 1, 10))
        self.assertEqual(gl.driver_count, 3)
        self.assertEqual([e.session for e in gl.records], ["04" * 16])

    def test_a_list_past_the_bound_is_refused(self):
        entry = f.encode_entry(4, b"\x01" * 16)
        self.assertEqual(f.decode_list(entry * 4096).driver_count, 4096)
        gl = f.decode_list(entry * 4097)
        self.assertTrue(gl.too_long)
        self.assertIsNone(gl.driver_count)

    def test_allowances(self):
        named = f.encode_entry(4, b"\x11" * 16, f.ALLOW_MAGIC)
        self.assertEqual(f.decode_allowance(named)[0], f.Allowance(4, "11" * 16))
        first = f.encode_entry(4, bytes(16), f.ALLOW_MAGIC)
        self.assertEqual(f.decode_allowance(first)[0], f.Allowance(4, None))
        self.assertEqual(f.decode_allowance(b""), (None, None))
        self.assertIsNone(f.decode_allowance(named[:20])[0])
        # A list entry is not an allowance.
        self.assertIsNone(f.decode_allowance(f.encode_entry(4, b"\x11" * 16))[0])

    def test_previous_values_are_measured_not_kept(self):
        data = f.previous_record(4, b"\x22" * 16, b"secret value") + b"AXGP"
        records, leftover = f.decode_previous(data)
        self.assertEqual(len(records), 1)
        self.assertEqual((records[0].kind, records[0].length, records[0].crc_ok), (4, 12, True))
        self.assertEqual(leftover, 4)
        self.assertNotIn("secret", repr(records))

    def test_lockout(self):
        self.assertTrue(f.lockout_locked(f.lockout_record(True)))
        self.assertFalse(f.lockout_locked(f.lockout_record(False)))
        self.assertFalse(f.lockout_locked(bytes(16)))


if __name__ == "__main__":
    unittest.main()
