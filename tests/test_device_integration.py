# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ndhn27

"""End-to-end tests against a real device and an IL2CPP app you are allowed to test.

They are SKIPPED unless IL2CPP_RE_TARGET is set, because they need a reachable frida-server and a real app:

    IL2CPP_RE_TARGET=com.example.unityapp python -m unittest tests.test_device_integration -v

Optional environment:
    IL2CPP_RE_REMOTE        frida-server address (default: the script's own default, 127.0.0.1:45861)
    IL2CPP_RE_OFFSET        a hook offset known to be GOOD for the build installed on the device
    IL2CPP_RE_STALE_OFFSET  an offset from an OLDER build (or any wrong one) to exercise the fallback

Each test drives the real dump_clean_header.py as a subprocess and checks the written file with the same
validator the tool uses. Nothing here is mocked - and nothing here has been run by the author of these
tests: they exist so that you can run them on your own device.
"""
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import dump_clean_header as d  # noqa: E402

TARGET = os.environ.get("IL2CPP_RE_TARGET")
REMOTE = os.environ.get("IL2CPP_RE_REMOTE")
OFFSET = os.environ.get("IL2CPP_RE_OFFSET")
STALE_OFFSET = os.environ.get("IL2CPP_RE_STALE_OFFSET")


def run_tool(tmp, *extra, timeout=300):
    out = os.path.join(tmp, "clean_header.bin")
    cmd = [sys.executable, os.path.join(ROOT, "dump_clean_header.py"), "--target", TARGET, "--out", out]
    if REMOTE:
        cmd += ["--remote", REMOTE]
    proc = subprocess.run(cmd + list(extra), capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    data = None
    if os.path.exists(out):
        with open(out, "rb") as f:
            data = f.read()
    return proc, data


@unittest.skipUnless(TARGET, "set IL2CPP_RE_TARGET=<bundle id> (and have frida-server reachable) to run the device tests")
class DeviceIntegration(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def assertCaptured(self, proc, data):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIsNotNone(data, "the tool reported success but wrote no file")
        check = d.validate_header(data)
        self.assertTrue(check.ok, check.errors)
        return check

    def test_full_scan_captures_a_valid_header(self):
        proc, data = run_tool(self.tmp)
        self.assertCaptured(proc, data)

    def test_instruction_mode_baseline_and_default_mode_capture_the_same_header(self):
        """The cheap default scan must not capture something different from the exhaustive baseline."""
        fast_proc, fast = run_tool(self.tmp)
        slow_proc, slow = run_tool(self.tmp, "--scan-mode", "instruction", "--scan-scope", "all")
        check = self.assertCaptured(fast_proc, fast)
        self.assertCaptured(slow_proc, slow)
        self.assertEqual(fast[:check.header_bytes], slow[:check.header_bytes])
        # Print both cost lines so the before/after is right there in the test output.
        for label, proc in (("default (block/module)", fast_proc), ("baseline (instruction/all)", slow_proc)):
            for line in proc.stdout.splitlines():
                if "Scan cost" in line:
                    print(f"\n[{label}] {line}")

    @unittest.skipUnless(OFFSET, "set IL2CPP_RE_OFFSET to a good offset for the installed build")
    def test_good_offset_takes_the_fast_path_in_a_single_launch(self):
        proc, data = run_tool(self.tmp, "--offset", OFFSET)
        self.assertCaptured(proc, data)
        self.assertNotIn("relaunching", proc.stdout)

    @unittest.skipUnless(STALE_OFFSET, "set IL2CPP_RE_STALE_OFFSET to an offset that is wrong for the installed build")
    def test_stale_offset_falls_back_and_still_produces_a_valid_header(self):
        proc, data = run_tool(self.tmp, "--offset", STALE_OFFSET)
        self.assertCaptured(proc, data)

    @unittest.skipUnless(STALE_OFFSET, "set IL2CPP_RE_STALE_OFFSET to an offset that is wrong for the installed build")
    def test_stale_offset_with_no_retry_fails_without_writing_a_file(self):
        proc, data = run_tool(self.tmp, "--offset", STALE_OFFSET, "--no-retry")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIsNone(data)

    def test_a_timeout_fails_cleanly_and_writes_nothing(self):
        proc, data = run_tool(self.tmp, "--timeout", "1")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIsNone(data)
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
