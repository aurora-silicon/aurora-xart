# SPDX-License-Identifier: MIT
"""status and list against synthetic Macs."""

import json
import os
import unittest

from fakemac import SECRET, WRAPPED, FakeMac
from aurora_xart.formats import Unfinished


class Base(unittest.TestCase):
    def mac(self, *a, **kw):
        m = FakeMac(*a, **kw)
        self.addCleanup(m.cleanup)
        return m

    def status(self, m):
        rc, out, err = m.run("status", "--json")
        self.assertEqual(err, "")
        return rc, json.loads(out)

    def codes(self, data):
        return {f["code"]: f for f in data["findings"]}


class StuckIntent(Base):
    def test_the_m1_intent_from_a_guarded_kernel_is_stuck(self):
        # The user's log: intent Guarded(0), xART guard list None.
        m = self.mac("m1", keybag="failed", touchid="failed")
        m.intent(Unfinished("guarded", 0))
        m.guard_list()
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertEqual(data["keybag"]["intent"], "Guarded(0)")
        self.assertIs(data["keybag"]["retry"], False)
        self.assertEqual(data["guard"]["level"], 0)
        self.assertIsNone(data["guard"]["listed"])
        stuck = self.codes(data)["keybag-intent-stuck"]
        self.assertEqual(stuck["level"], "error")
        self.assertIn("linux#1049", stuck["message"])
        self.assertIn("aurora-xart reset-touchid", stuck["action"])
        rc, out, _ = m.run("status")
        self.assertEqual(rc, 1)
        self.assertIn("never finished", out)
        self.assertIn("Guarded(0); the driver will not send it again", out)

    def test_the_same_intent_under_an_unchanged_list_is_sent_again(self):
        m = self.mac("m2pro", keybag="failed")
        m.intent(Unfinished("guarded", 2))
        m.guard_list(1, 2)
        rc, data = self.status(m)
        self.assertEqual(rc, 0)
        self.assertIs(data["keybag"]["retry"], True)
        self.assertIn("keybag-intent-retry", self.codes(data))

    def test_a_list_that_grew_keeps_it_stuck(self):
        m = self.mac("m2pro", keybag="failed")
        m.intent(Unfinished("guarded", 2))
        m.guard_list(1, 2, 3)
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("grew from 2 to 3", self.codes(data)["keybag-intent-stuck"]["message"])

    def test_an_unguarded_intent_is_never_sent_again(self):
        m = self.mac("m2pro", keybag="failed")
        m.intent(Unfinished("unguarded"))
        m.guard_list()
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("never listed", self.codes(data)["keybag-intent-stuck"]["message"])

    def test_a_torn_intent_is_stuck(self):
        m = self.mac("m1", keybag="failed")
        m.intent(Unfinished("guarded", 0))
        data = bytearray(m.read("/var/lib/aurora-sep-keybag.bin"))
        data[0x28] ^= 1
        m.write("/var/lib/aurora-sep-keybag.bin", bytes(data))
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("damaged", self.codes(data)["keybag-intent-stuck"]["message"])


class Committed(Base):
    def test_a_committed_bag_is_fine(self):
        m = self.mac("m2pro")
        m.committed()
        m.touchid_state()
        m.guard_list(1)
        rc, data = self.status(m)
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "ok")
        self.assertEqual(data["keybag"]["state"], "committed")
        self.assertEqual(data["keybag"]["provenance"], "host-generated")
        rc, out, _ = m.run("status")
        self.assertIn("Nothing wrong found.", out)

    def test_a_bag_that_does_not_load(self):
        m = self.mac("m2pro", keybag="failed", touchid="failed")
        m.committed()
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("keybag-does-not-load", self.codes(data))

    def test_a_damaged_bag(self):
        m = self.mac("m2pro", keybag="failed")
        m.committed()
        m.write("/var/lib/aurora-sep-keybag.bin", m.read("/var/lib/aurora-sep-keybag.bin")[:-3])
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("keybag-damaged", self.codes(data))

    def test_no_key_material_is_printed(self):
        m = self.mac("m2pro")
        m.committed()
        m.touchid_state()
        for argv in (["status"], ["status", "--json"], ["list"], ["list", "--json"]):
            _, out, _ = m.run(*argv)
            for secret in (SECRET.hex(), WRAPPED[:8].hex(), "old value"):
                self.assertNotIn(secret, out, argv)


class Refused(Base):
    def test_a_refused_create_is_retried_by_the_driver(self):
        m = self.mac("m3", keybag="missing")
        m.refused()
        rc, data = self.status(m)
        self.assertEqual(rc, 0)
        self.assertEqual(data["keybag"]["state"], "refused")
        self.assertEqual(data["keybag"]["driver_read"], "absent")
        self.assertIn("keybag-refused", self.codes(data))


class List(Base):
    def test_records_and_a_torn_entry(self):
        m = self.mac("m2pro")
        m.committed()
        m.touchid_state()
        good = __import__("aurora_xart.formats", fromlist=["x"]).encode_entry(4, b"\x02" * 16)
        torn = bytearray(good)
        torn[12] ^= 1
        m.guard_list(1, extra=bytes(torn) + good[:7])
        rc, out, _ = m.run("list", "--json")
        data = json.loads(out)
        lst = data["guard_list"]
        self.assertEqual((lst["entries"], lst["records"], lst["torn"], lst["tail_bytes"]),
                         (2, 1, 1, 7))
        self.assertEqual(lst["items"][0], {"index": 0, "kind": 4, "session": "01" * 16,
                                           "torn": False, "repeated": False})
        self.assertTrue(lst["items"][1]["torn"])
        codes = {f["code"] for f in data["findings"]}
        self.assertTrue({"guard-list-torn", "guard-list-tail"} <= codes)
        self.assertEqual(data["keybag"]["uuid"], "0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        self.assertEqual(sorted(data["fprint"]["dirs"]),
                         ["/var/lib/fprint/dj/apple-sep", "/var/lib/fprint/root/apple-sep"])
        self.assertEqual(data["previous"]["records"][0]["length"], len(b"old value"))
        rc, out, _ = m.run("list")
        self.assertIn("torn entry, ignored by the driver", out)
        self.assertIn("01" * 16, out)

    def test_a_linked_firmware_directory_lists_calibration_once(self):
        m = self.mac("m2pro")
        m.write("/usr/lib/firmware/apple/mesa_calibration.bin", b"C", 0o644)
        os.symlink("usr/lib", m.p("/lib"))
        _, out, _ = m.run("list", "--json")
        self.assertEqual(json.loads(out)["calibration"],
                         ["/usr/lib/firmware/apple/mesa_calibration.bin"])

    def test_an_armed_allowance(self):
        from aurora_xart import formats
        m = self.mac("m2pro")
        m.committed()
        m.write("/var/lib/aurora-sep-xart-allow-once.bin",
                formats.encode_entry(4, bytes(16), formats.ALLOW_MAGIC))
        _, out, _ = m.run("list")
        self.assertIn("the first existing kind-4 record", out)


class Configuration(Base):
    def test_a_read_only_install(self):
        m = self.mac("m2pro", xart="disabled", keybag="missing", touchid="failed",
                     xart_guard="0", xart_guard_list="none")
        m.write("/etc/modprobe.d/aurora-sep.conf",
                "options apple_sep xart_writes=0 provision_keybag=0\n", 0o644)
        rc, data = self.status(m)
        self.assertTrue(data["read_only"]["value"])
        codes = self.codes(data)
        self.assertIn("read-only", codes)
        self.assertIn("not-provisioned", codes)
        self.assertEqual(data["params"]["xart_writes"]["value"], 0)

    def test_the_owners_file_that_enables_writes_is_not_read_only(self):
        # The M2 Pro's own /etc/modprobe.d/aurora-sep.conf turns writes on.
        m = self.mac("m2pro")
        m.write("/etc/modprobe.d/aurora-sep.conf",
                "options apple_sep xart_writes=1 provision_keybag=1\n", 0o644)
        _, data = self.status(m)
        self.assertFalse(data["read_only"]["value"])

    def test_parameter_precedence(self):
        m = self.mac("m2pro")
        m.write("/usr/lib/modprobe.d/50-sep.conf", "options apple_sep xart_guard=2\n", 0o644)
        m.write("/etc/modprobe.d/50-sep.conf", "options apple_sep xart_guard=0\n", 0o644)
        m.write("/usr/lib/modprobe.d/60-sep.conf", "options apple-sep provision_keybag=0\n",
                0o644)
        _, data = self.status(m)
        # /etc hides the same name in /usr/lib; later files win.
        self.assertEqual(data["params"]["xart_guard"],
                         {"value": 0, "source": "/etc/modprobe.d/50-sep.conf:1"})
        self.assertEqual(data["params"]["provision_keybag"]["value"], 0)
        m.write("/proc/cmdline", b"root=x apple_sep.xart_guard=1\n")
        _, data = self.status(m)
        self.assertEqual(data["params"]["xart_guard"],
                         {"value": 1, "source": "kernel command line"})

    def test_no_driver(self):
        m = self.mac("m2pro", driver=False)
        rc, data = self.status(m)
        self.assertIn("driver-not-running", self.codes(data))
        # Without the driver's report the level comes from the configuration.
        self.assertEqual(data["guard"], {"level": 1, "source": "configuration", "list": None,
                                         "refusals": None, "matching": None, "listed": 0})

    def test_guard_refusals_are_not_a_reset_case(self):
        m = self.mac("m2pro", xart_guard_refusals="2", matching="blocked")
        m.committed()
        rc, data = self.status(m)
        refused = self.codes(data)["guard-refused"]
        self.assertIn("does not help", refused["action"])

    def test_not_a_mac(self):
        m = self.mac("m2pro")
        m.write("/proc/device-tree/compatible", b"qemu,virt\0")
        rc, data = self.status(m)
        self.assertEqual(rc, 1)
        self.assertIn("not-apple-silicon", self.codes(data))


@unittest.skipIf(os.geteuid() == 0, "root reads everything")
class WithoutRoot(Base):
    def test_unreadable_files_say_root_is_needed(self):
        m = self.mac("m1", keybag="failed")
        m.intent(Unfinished("guarded", 0))
        os.chmod(m.p("/var/lib/aurora-sep-keybag.bin"), 0)
        self.addCleanup(os.chmod, m.p("/var/lib/aurora-sep-keybag.bin"), 0o600)
        rc, data = self.status(m)
        self.assertEqual(data["keybag"]["error"], "needs root")
        finding = self.codes(data)["needs-root"]
        self.assertIn("sudo aurora-xart status", finding["action"])


if __name__ == "__main__":
    unittest.main()
