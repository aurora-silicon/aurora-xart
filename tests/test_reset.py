# SPDX-License-Identifier: MIT
"""reset-touchid against synthetic Macs: the refusals, the move and its rollback."""

import os
import unittest
from unittest import mock

from fakemac import FakeMac
from aurora_xart import ops, system
from aurora_xart.formats import Unfinished

STAMP = "20261107-120000"
DEST = "/var/lib/aurora-sep-touchid-reset-" + STAMP
MOVED = [p for p in system.TOUCHID_STATE_FILES if p != system.REFKEY_V2]
KEPT = [system.OWNED, system.ALLOW, system.PREVIOUS, system.LOCKOUT,
        "/usr/lib/firmware/apple/mesa_calibration.bin", "/var/lib/fprint/dj/other-driver/0/1"]


class Reset(unittest.TestCase):
    def setUp(self):
        stamp = mock.patch("aurora_xart.ops.time.strftime", return_value=STAMP)
        stamp.start()
        self.addCleanup(stamp.stop)

    def stuck_m1(self, **diag):
        m = FakeMac("m1", keybag="failed", touchid="failed", **diag)
        self.addCleanup(m.cleanup)
        m.intent(Unfinished("guarded", 0))
        m.touchid_state()
        m.guard_list()
        return m

    def snapshot(self, m):
        files = {}
        for path in m.root.rglob("*"):
            if path.is_file() and "/sys/" not in str(path) and "/proc/" not in str(path):
                files[str(path.relative_to(m.root))] = path.read_bytes()
        return files

    def assert_unchanged(self, m, before):
        self.assertEqual(self.snapshot(m), before)
        self.assertFalse(m.p(DEST).exists())

    def test_the_stuck_m1_is_reset(self):
        m = self.stuck_m1()
        before = self.snapshot(m)
        rc, out, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 0, err)
        for path in MOVED:
            self.assertFalse(m.p(path).exists(), path)
            name = path.rsplit("/", 1)[1]
            self.assertEqual(m.read(f"{DEST}/{name}"), before[path.lstrip("/")])
        for user in ("dj", "root"):
            self.assertFalse(m.p(f"/var/lib/fprint/{user}/apple-sep").exists())
            self.assertEqual(m.read(f"{DEST}/fprint/{user}/apple-sep/0/7"),
                             b"print-" + user.encode())
        for path in KEPT:
            self.assertEqual(m.read(path), before[path.lstrip("/")], path)
        self.assertEqual(oct(m.p(DEST).stat().st_mode & 0o777), "0o700")
        self.assertIn("never finished", out)
        self.assertIn("enrolled fingerprint", out)
        self.assertIn("Reboot now", out)
        # Under --root this system's fprintd was left alone, and it says so.
        self.assertIn("leaving this system's fprintd alone", out)
        self.assertNotIn("stays masked", out)

    def test_the_keybag_moves_last(self):
        m = self.stuck_m1()
        order = []
        real = os.rename

        def rename(src, dst):
            order.append(str(src))
            return real(src, dst)

        with mock.patch("aurora_xart.ops.os.rename", rename):
            rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertTrue(order[-1].endswith("aurora-sep-keybag.bin"))
        self.assertTrue(order[0].endswith("fprint/dj/apple-sep"))

    def test_a_failed_move_puts_everything_back(self):
        m = self.stuck_m1()
        before = self.snapshot(m)
        real = os.rename

        def rename(src, dst):
            if str(src).endswith("aurora-sep-refkey.bin"):
                raise OSError(5, "Input/output error")
            return real(src, dst)

        with mock.patch("aurora_xart.ops.os.rename", rename):
            rc, out, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("put back everything already moved", err)
        self.assertEqual(self.snapshot(m), before)

    def test_the_rollback_unmasks_fprintd_on_a_live_system(self):
        m = self.stuck_m1()
        calls = []
        real = os.rename

        def rename(src, dst):
            if str(src).endswith("aurora-sep-keybag.bin"):
                raise OSError(18, "Invalid cross-device link")
            return real(src, dst)

        with mock.patch.object(system.Root, "is_live", True), \
                mock.patch("aurora_xart.ops.os.geteuid", return_value=0), \
                mock.patch("aurora_xart.ops.os.rename", rename):
            rc, _, err = m.run("reset-touchid", "--yes", calls=calls)
        self.assertEqual(rc, 2, err)
        self.assertEqual(calls, [["systemctl", "mask", "--runtime", "--now", "fprintd.service"],
                                 ["systemctl", "unmask", "--runtime", "fprintd.service"]])

    def test_a_live_reset_stops_fprintd_first(self):
        m = self.stuck_m1()
        calls = []
        with mock.patch.object(system.Root, "is_live", True), \
                mock.patch("aurora_xart.ops.os.geteuid", return_value=0):
            rc, out, err = m.run("reset-touchid", "--yes", calls=calls)
        self.assertEqual(rc, 0, err)
        self.assertEqual(calls, [["systemctl", "mask", "--runtime", "--now", "fprintd.service"]])
        self.assertIn("fprintd stays masked", out)

    def test_fprintd_that_will_not_stop_blocks_the_reset(self):
        m = self.stuck_m1()
        before = self.snapshot(m)
        with mock.patch.object(system.Root, "is_live", True), \
                mock.patch("aurora_xart.ops.os.geteuid", return_value=0):
            rc, _, err = m.run("reset-touchid", "--yes", runner=lambda cmd, t: 1)
        self.assertEqual(rc, 2)
        self.assertIn("could not stop fprintd", err)
        self.assert_unchanged(m, before)

    def test_root_is_needed_on_a_live_system(self):
        m = self.stuck_m1()
        with mock.patch.object(system.Root, "is_live", True), \
                mock.patch("aurora_xart.ops.os.geteuid", return_value=1000):
            rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("needs root", err)

    def test_a_read_only_install_is_refused(self):
        m = self.stuck_m1()
        m.write(system.MODPROBE_CONF, "options apple_sep xart_writes=0 provision_keybag=0\n")
        before = self.snapshot(m)
        rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("installed read-only", err)
        self.assert_unchanged(m, before)

    def test_no_driver_is_refused(self):
        m = self.stuck_m1()
        for name in ("keybag", "touchid", "xart_guard"):
            m.set_diag(**{name: None})
        before = self.snapshot(m)
        rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("driver is not running", err)
        self.assert_unchanged(m, before)

    def test_a_working_keybag_needs_force(self):
        m = FakeMac("m2pro")
        self.addCleanup(m.cleanup)
        m.committed()
        m.touchid_state()
        before = self.snapshot(m)
        rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("not broken", err)
        self.assert_unchanged(m, before)
        rc, _, err = m.run("reset-touchid", "--yes", "--force")
        self.assertEqual(rc, 0, err)
        self.assertIn("--force", err)
        self.assertFalse(m.p(system.KEYBAG).exists())

    def test_an_unopened_sensor_is_opened_once_before_judging(self):
        m = FakeMac("m2pro")
        self.addCleanup(m.cleanup)
        m.committed()
        calls = []

        def runner(cmd, timeout):
            calls.append((list(cmd), timeout))
            if cmd[0] == "fprintd-list":
                m.set_diag(keybag="failed", touchid="failed")
            return 0

        with mock.patch.object(system.Root, "is_live", True), \
                mock.patch("aurora_xart.ops.os.geteuid", return_value=0):
            rc, _, err = m.run("reset-touchid", "--yes", runner=runner)
        self.assertEqual(rc, 0, err)
        self.assertEqual(calls[0], (["fprintd-list", "root"], 20))

    def test_nothing_to_reset(self):
        m = FakeMac("m2pro", keybag="missing")
        self.addCleanup(m.cleanup)
        rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("nothing to reset", err)

    def test_it_asks_for_reset_unless_yes(self):
        m = self.stuck_m1()
        before = self.snapshot(m)
        asked = []

        def answer(word):
            def confirm(prompt, expected):
                asked.append((prompt, expected))
                return word == expected
            return confirm

        with mock.patch("aurora_xart.ops.confirm_on_tty", answer("reset")):
            rc, _, err = m.run("reset-touchid")
        self.assertEqual(rc, 2)
        self.assertEqual(asked, [("Type RESET to continue: ", "RESET")])
        self.assertIn("not reset", err)
        self.assert_unchanged(m, before)
        with mock.patch("aurora_xart.ops.confirm_on_tty", answer("RESET")):
            rc, _, err = m.run("reset-touchid")
        self.assertEqual(rc, 0, err)
        self.assertFalse(m.p(system.KEYBAG).exists())

    def test_without_a_terminal_it_says_to_use_yes(self):
        with mock.patch("builtins.open", side_effect=OSError(6, "No such device")), \
                self.assertRaisesRegex(ops.Refusal, "--yes"):
            ops.confirm_on_tty("Type RESET to continue: ", "RESET")

    def test_a_second_reset_in_the_same_second_gets_its_own_directory(self):
        m = self.stuck_m1()
        m.p(DEST).mkdir()
        rc, _, err = m.run("reset-touchid", "--yes")
        self.assertEqual(rc, 0, err)
        self.assertTrue(m.p(DEST + "-1/aurora-sep-keybag.bin").exists())


if __name__ == "__main__":
    unittest.main()
