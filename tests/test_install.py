# SPDX-License-Identifier: MIT
"""The installed layout runs: the launcher finds its package in share/."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fakemac import FakeMac

REPO = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make") and shutil.which("install"), "needs make")
class Installed(unittest.TestCase):
    def test_make_install_runs(self):
        with tempfile.TemporaryDirectory() as dest:
            subprocess.run(["make", "-s", "-C", str(REPO), "install", f"DESTDIR={dest}",
                            "PREFIX=/usr"], check=True)
            launcher = Path(dest, "usr/bin/aurora-xart")
            self.assertTrue(Path(dest, "usr/share/aurora-xart/aurora_xart/cli.py").is_file())
            self.assertTrue(Path(dest, "usr/share/man/man8/aurora-xart.8").is_file())
            m = FakeMac("m2pro")
            self.addCleanup(m.cleanup)
            m.committed()
            # A copy away from the checkout, so only the installed package is found.
            run = subprocess.run([sys.executable, "-I", str(launcher), "--root", str(m.root),
                                  "status", "--json"], capture_output=True, text=True,
                                 cwd=dest, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)["keybag"]["state"], "committed")


if __name__ == "__main__":
    unittest.main()
