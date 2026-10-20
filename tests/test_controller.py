# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 ndhn27

"""Controller flow tests (retry, validation gate, output files) against a fake `frida` module.

Run from the repo root:  python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dump_clean_header as d  # noqa: E402
from test_validate_header import build_header  # noqa: E402

AGENT = os.path.join(ROOT, "agents", "dump_clean_header_v4.js")
GOOD = bytes(build_header(29))
MAGIC_ONLY = d.REAL_MAGIC.to_bytes(4, "little") + (29).to_bytes(4, "little") + bytes(1016)


class FakeFrida:
    """Each entry of `attempts` scripts one spawn: header returned, status, whether configure() exists, and
    optional failures (configure_error, load_error, attach_error, wait_error, unload_error).

    `events` records the order of lifecycle calls so tests can check that nothing is left behind."""

    def __init__(self, attempts):
        self.attempts = list(attempts)
        self.spawned = []
        self.killed = []
        self.configs = []
        self.events = []
        outer = self

        class Exports:
            def __init__(self, plan):
                self.plan = plan

            def configure(self, cfg):
                if not self.plan.get("has_configure", True):
                    raise RuntimeError("unable to find method 'configure'")
                if self.plan.get("configure_error"):
                    raise RuntimeError(self.plan["configure_error"])
                outer.configs.append(cfg)

            def wait_for_header(self, timeout):
                outer.events.append("wait")
                if "wait_error" in self.plan:
                    raise self.plan["wait_error"]
                return self.plan.get("header")

            def get_status(self):
                return self.plan.get("status")

            def cancel(self, why=None):
                outer.events.append("cancel")

        class Script:
            def __init__(self, plan):
                self.plan = plan
                self.exports_sync = Exports(plan)

            def on(self, *a):
                pass

            def load(self):
                if self.plan.get("load_error"):
                    raise RuntimeError(self.plan["load_error"])

            def unload(self):
                outer.events.append("unload")
                if self.plan.get("unload_error"):
                    raise RuntimeError("unload failed")

        class Session:
            def __init__(self, plan):
                self.plan = plan

            def on(self, *a):
                pass

            def create_script(self, source):
                return Script(self.plan)

            def detach(self):
                outer.events.append("detach")

        class Device:
            def spawn(self, argv):
                outer.spawned.append(argv)
                return 100 + len(outer.spawned)

            def attach(self, pid):
                plan = outer.attempts[len(outer.spawned) - 1]
                if plan.get("attach_error"):
                    raise RuntimeError(plan["attach_error"])
                return Session(plan)

            def resume(self, pid):
                outer.events.append("resume")

            def kill(self, pid):
                outer.killed.append(pid)
                outer.events.append(f"kill:{pid}")

        manager = types.SimpleNamespace(add_remote_device=lambda remote: Device())
        self.module = types.ModuleType("frida")
        self.module.get_device_manager = lambda: manager


def read_or_none(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()


def run_main(attempts, *extra):
    fake = FakeFrida(attempts)
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "clean_header.bin")
        argv = ["dump_clean_header.py", "--target", "com.example.app", "--agent", AGENT, "--out", out, *extra]
        buf = io.StringIO()
        code = 0
        with mock.patch.dict(sys.modules, {"frida": fake.module}), mock.patch.object(sys, "argv", argv), \
                mock.patch.object(d.time, "sleep"), contextlib.redirect_stdout(buf):
            try:
                d.main()
            except SystemExit as exc:
                code = exc.code
        written = read_or_none(out)
        rejected = read_or_none(os.path.join(tmp, "clean_header.rejected.bin"))
    return fake, code, written, rejected, buf.getvalue()


FAILED = {"header": None, "status": {"resolved": True, "reason": "il2cpp_init returned without a validated header"}}


class ControllerFlow(unittest.TestCase):
    def test_valid_header_is_written(self):
        fake, code, written, rejected, _ = run_main([{"header": GOOD, "status": {"method": "fast-offset"}}], "--offset", "0xab6ad08")
        self.assertEqual(code, 0)
        self.assertEqual(written, GOOD)
        self.assertEqual(len(fake.spawned), 1)
        self.assertEqual(fake.configs[0]["offset"], "0xab6ad08")

    def test_failed_offset_run_relaunches_with_full_scan(self):
        fake, code, written, _, _ = run_main([FAILED, {"header": GOOD, "status": {"method": "dynamic-scan"}}], "--offset", "0xab6ad08")
        self.assertEqual(code, 0)
        self.assertEqual(written, GOOD)
        self.assertEqual(len(fake.spawned), 2)
        self.assertEqual(fake.killed, [101])
        self.assertEqual(fake.configs[0]["offset"], "0xab6ad08")
        self.assertIsNone(fake.configs[1]["offset"], "the retry must run the scan without the stale offset")

    def test_no_retry_flag(self):
        fake, code, written, _, _ = run_main([FAILED], "--offset", "0xab6ad08", "--no-retry")
        self.assertEqual(code, 1)
        self.assertIsNone(written)
        self.assertEqual(len(fake.spawned), 1)

    def test_no_retry_without_offset_or_with_eager_scan(self):
        for extra in ([], ["--offset", "0x10", "--eager-scan"]):
            with self.subTest(extra=extra):
                fake, code, _, _, _ = run_main([FAILED], *extra)
                self.assertEqual(code, 1)
                self.assertEqual(len(fake.spawned), 1)
        fake, *_ = run_main([FAILED], "--offset", "0x10", "--eager-scan")
        self.assertTrue(fake.configs[0]["eagerScan"])

    def test_no_retry_for_legacy_agents_without_configure(self):
        fake, code, *_ = run_main([{"header": None, "has_configure": False}], "--offset", "0x10")
        self.assertEqual(code, 1)
        self.assertEqual(len(fake.spawned), 1)

    def test_magic_only_dump_from_a_legacy_agent_is_not_written(self):
        _, code, written, rejected, out = run_main([{"header": MAGIC_ONLY, "has_configure": False}])
        self.assertEqual(code, 2)
        self.assertIsNone(written)
        self.assertEqual(rejected, MAGIC_ONLY)
        self.assertIn("failed validation", out)
        self.assertIn("--lenient", out)

    def test_lenient_writes_a_structurally_broken_dump(self):
        _, code, written, rejected, out = run_main([{"header": MAGIC_ONLY, "has_configure": False}], "--lenient")
        self.assertEqual(code, 0)
        self.assertEqual(written, MAGIC_ONLY)
        self.assertIn("(lenient)", out)

    def test_lenient_and_header_size_reach_the_agent(self):
        fake, *_ = run_main([{"header": GOOD}], "--lenient", "--header-size", "512")
        self.assertTrue(fake.configs[0]["lenient"])
        self.assertEqual(fake.configs[0]["headerSize"], 512)

    def test_header_size_below_the_largest_known_header_is_refused(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
            argv = ["x", "--target", "t", "--header-size", "200"]
            with mock.patch.object(sys, "argv", argv):
                d.parse_args()
        self.assertEqual(ctx.exception.code, 2)


class Lifecycle(unittest.TestCase):
    """What happens to the spawned process and the agent on every way a run can end."""

    def test_success_unloads_and_detaches_but_leaves_the_app_running(self):
        fake, code, written, _, _ = run_main([{"header": GOOD}])
        self.assertEqual(code, 0)
        self.assertEqual(written, GOOD)
        self.assertEqual(fake.events, ["resume", "wait", "unload", "detach"])
        self.assertEqual(fake.killed, [])

    def test_failed_run_cancels_the_agent_then_unloads_detaches_and_kills_the_app(self):
        fake, code, written, _, _ = run_main([FAILED])
        self.assertEqual(code, 1)
        self.assertIsNone(written)
        self.assertEqual(fake.events, ["resume", "wait", "cancel", "unload", "detach", "kill:101"])

    def test_each_failed_attempt_is_cleaned_up_before_the_next_spawn(self):
        fake, code, *_ = run_main([FAILED, FAILED], "--offset", "0x10")
        self.assertEqual(code, 1)
        self.assertEqual(fake.killed, [101, 102])
        self.assertEqual(fake.events.count("unload"), 2)
        self.assertEqual(fake.events.count("detach"), 2)

    def test_a_crash_during_the_wait_is_reported_cleanly_and_triggers_the_retry(self):
        crash = {"wait_error": RuntimeError("script has been destroyed"), "status": None}
        fake, code, written, _, out = run_main([crash, {"header": GOOD}], "--offset", "0xab6ad08")
        self.assertEqual(code, 0)
        self.assertEqual(written, GOOD)
        self.assertIn("wait_for_header() failed: script has been destroyed", out)
        self.assertEqual(fake.killed, [101])
        self.assertIsNone(fake.configs[1]["offset"])

    def test_ctrl_c_during_the_wait_cancels_cleans_up_and_exits_130(self):
        fake, code, written, rejected, out = run_main([{"wait_error": KeyboardInterrupt()}])
        self.assertEqual(code, 130)
        self.assertIsNone(written)
        self.assertEqual(len(fake.spawned), 1, "an interrupted run must not be retried")
        self.assertEqual(fake.events, ["resume", "wait", "cancel", "unload", "detach", "kill:101"])
        self.assertIn("Interrupted", out)

    def test_a_rejected_configuration_aborts_before_the_app_is_resumed(self):
        fake, code, written, _, out = run_main([{"configure_error": "headerSize must be an integer"}])
        self.assertEqual(code, 1)
        self.assertIsNone(written)
        self.assertNotIn("resume", fake.events)
        self.assertEqual(fake.killed, [101], "the suspended app must not be left behind")
        self.assertIn("the agent rejected its configuration", out)

    def test_a_script_that_fails_to_load_does_not_leave_a_suspended_app(self):
        fake, code, *_ = run_main([{"load_error": "SyntaxError: unexpected token"}])
        self.assertEqual(code, 1)
        self.assertNotIn("resume", fake.events)
        self.assertEqual(fake.killed, [101])

    def test_a_failing_attach_does_not_leave_a_suspended_app(self):
        fake, code, *_ = run_main([{"attach_error": "unable to attach"}])
        self.assertEqual(code, 1)
        self.assertEqual(fake.killed, [101])

    def test_an_error_while_unloading_does_not_stop_the_rest_of_the_cleanup(self):
        fake, code, *_ = run_main([{"header": None, "unload_error": True}])
        self.assertEqual(code, 1)
        self.assertEqual(fake.events[-3:], ["unload", "detach", "kill:101"])


class ScanOptions(unittest.TestCase):
    def test_defaults_are_block_mode_and_module_scope(self):
        fake, *_ = run_main([{"header": GOOD}])
        self.assertEqual(fake.configs[0]["scanMode"], "block")
        self.assertEqual(fake.configs[0]["scanScope"], "module")
        self.assertNotIn("scanRange", fake.configs[0])

    def test_options_reach_the_agent(self):
        fake, *_ = run_main([{"header": GOOD}], "--scan-mode", "instruction", "--scan-scope", "all")
        self.assertEqual(fake.configs[0]["scanMode"], "instruction")
        self.assertEqual(fake.configs[0]["scanScope"], "all")

    def test_scan_range_is_passed_as_hex_strings(self):
        fake, *_ = run_main([{"header": GOOD}], "--scan-range", "0xa00000:0xa40000")
        self.assertEqual(fake.configs[0]["scanRange"], ["0xa00000", "0xa40000"])

    def test_the_retry_after_a_failed_offset_keeps_the_scan_options(self):
        fake, *_ = run_main([FAILED, {"header": GOOD}], "--offset", "0x10", "--scan-range", "0x100:0x200", "--scan-mode", "instruction")
        self.assertEqual(fake.configs[1]["scanRange"], ["0x100", "0x200"])
        self.assertEqual(fake.configs[1]["scanMode"], "instruction")

    def test_bad_scan_options_are_refused(self):
        for extra in (["--scan-range", "0x20:0x10"], ["--scan-range", "nonsense"], ["--scan-range", "0x10"],
                      ["--scan-range", "-1:5"], ["--scan-range", "0x10:0x20", "--scan-scope", "all"],
                      ["--scan-mode", "everything"], ["--scan-scope", "galaxy"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                with mock.patch.object(sys, "argv", ["x", "--target", "t", *extra]):
                    d.parse_args()
            self.assertEqual(ctx.exception.code, 2)

    def test_agent_statistics_and_found_at_are_printed(self):
        status = {
            "phase": "done", "outcome": "captured", "method": "dynamic-scan",
            "scan": {"mode": "block", "scope": "module"},
            "stats": {"blocksCompiled": 40, "blocksInstrumented": 12, "calloutRuns": 3000, "regChecks": 9000,
                      "scanMs": 850, "msFromInitEntry": 1200},
            "foundAt": {"reg": "x22", "pcOffset": "0xb12345"},
        }
        _, code, _, _, out = run_main([{"header": GOOD, "status": status}])
        self.assertEqual(code, 0)
        self.assertIn("blocks instrumented/compiled=12/40", out)
        self.assertIn("callouts=3000", out)
        self.assertIn("scan time=850 ms", out)
        self.assertIn("x22 at UnityFramework+0xb12345", out)


if __name__ == "__main__":
    unittest.main()
