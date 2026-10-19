import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from warden import operation_state as o, core, linux
from warden.tui import details, overview, page_lines


class OperationStateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.channel = {"id": "forpost1", "if": "awgfp1"}
        self.owner = {"pid": os.getpid(), "start_ticks": 42, "boot": "test-boot"}
        for p in (patch.object(o, "ROOT", self.root / "operations"),
                  patch.object(o, "identity", return_value=self.owner.copy()),
                  patch.object(o, "trusted")):  # Linux /run permissions are tested separately.
            p.start()
            self.addCleanup(p.stop)
        def atomic(path, data):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.ctl = types.SimpleNamespace(p=types.SimpleNamespace(atomic=atomic, Refuse=RuntimeError),
                                        say=Mock(), encode=lambda d: json.dumps(d).encode())
        self.path = o.ROOT / "awgfp1.json"

    def test_live_phases_and_cleanup_on_success_or_error(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                try:
                    with o.observe(self.ctl, self.channel, "start") as update:
                        self.assertEqual(o.read("forpost1", "awgfp1")["phase"], "Starting")
                        update("Waiting for server")
                        self.assertEqual(o.read("forpost1", "awgfp1")["phase"], "Waiting for server")
                        if fail:
                            raise RuntimeError("rollback")
                except RuntimeError:
                    pass
                self.assertFalse(self.path.exists())
                self.assertIsNone(o.read("forpost1", "awgfp1"))

    def test_stale_pid_reuse_reboot_wrong_entity_and_bad_records_ignored(self):
        with o.observe(self.ctl, self.channel, "start"):
            saved = json.loads(self.path.read_text())
            for change in ({"start_ticks": 43}, {"boot": "previous-boot"}, {"id": "other"},
                           {"interface": "awgfp9"}, {"pid": True}, {"phase": "unrecognized"},
                           {"action": "stop", "phase": "Waiting for server"}, {"version": 2}):
                self.path.write_text(json.dumps(dict(saved, **change)))
                self.assertIsNone(o.read("forpost1", "awgfp1"), change)
            for raw in ("{broken", "[]", "x"*4097):
                self.path.write_text(raw)
                self.assertIsNone(o.read("forpost1", "awgfp1"))
            self.path.write_text(json.dumps(saved))
            with patch.object(o, "identity", side_effect=ProcessLookupError()):
                self.assertIsNone(o.read("forpost1", "awgfp1"))
            self.assertIsNone(o.read("forpost1", "../../etc/passwd"))

    def test_progress_io_failure_does_not_replace_backend_failure(self):
        self.ctl.p.atomic = Mock(side_effect=RuntimeError("filesystem error"))
        with self.assertRaisesRegex(ValueError, "backend failure"):
            with o.observe(self.ctl, self.channel, "start"):
                raise ValueError("backend failure")
        self.assertTrue(self.ctl.say.called)

    def test_collector_shows_phase_without_hiding_actual_active_route(self):
        registry = self.root / "channels.json"
        registry.write_text(json.dumps({"version": 2, "channels": [dict(self.channel,
            peer="10.78.0.1", local="10.78.0.2", public="192.0.2.1", rank=40,
            enabled=False, maintenance=True, stopped=True)]}))
        cfg = dict(core.DEFAULTS, registry=str(registry))
        runner = lambda argv: "[]" if "-j" in argv else ""
        def collect():
            with patch.object(linux, "read_json", side_effect=OSError()):
                return linux.collect(cfg, runner=runner)["tunnels"][0]
        with o.observe(self.ctl, self.channel, "start") as update:
            update("Waiting for server")
            row = collect()
            self.assertEqual((row["role"], row["health"]), ("Starting", "Unknown"))
            self.assertEqual(row["operation_phase"], "Waiting for server")
            self.assertIn("Waiting for server", " ".join(details(row)))
            data = dict(tunnels=[row], timestamp=0, controller=dict(active="primary", version="registry-v2", fresh=True),
                        services=[], warnings=[])
            self.assertIn("Starting / Waiting for server", " ".join(overview(data)))
            self.assertIn("CHANNEL OPERATIONS", " ".join(page_lines(data, 1, 0, cfg)))
            with patch.object(linux, "active_route", return_value="forpost1"):
                self.assertEqual(collect()["role"], "Active")
        self.assertEqual(collect()["role"], "Stopped")


class ProcessIdentityTests(unittest.TestCase):
    def test_stat_parsing_with_spaces_and_parentheses_and_zombie(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(o, "PROC", Path(tmp)):
            stat = Path(tmp) / "123/stat"
            stat.parent.mkdir()
            boot = Path(tmp) / "sys/kernel/random/boot_id"
            boot.parent.mkdir(parents=True)
            boot.write_text("test-boot\n")
            stat.write_text("123 (worker ) name) S " + "0 "*18 + "9876 0 0\n")
            self.assertEqual(o.identity(123), {"pid": 123, "start_ticks": 9876, "boot": "test-boot"})
            stat.write_text(stat.read_text().replace(") S ", ") Z "))
            with self.assertRaises(ValueError):
                o.identity(123)

    def test_untrusted_owner_and_writable_paths_refused(self):
        for uid, mode in ((1000, 0o755), (0, 0o777)):
            with patch.object(o.Path, "stat", return_value=types.SimpleNamespace(st_uid=uid, st_mode=mode)):
                with self.assertRaises(ValueError):
                    o.trusted(Path.cwd() / "file")

    @unittest.skipUnless(sys.platform == "linux", "Linux process identity")
    def test_real_process_identity_disappears_after_exit(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
        try:
            owner = o.identity(proc.pid)
            self.assertEqual(owner["pid"], proc.pid)
            self.assertGreater(owner["start_ticks"], 0)
        finally:
            proc.terminate()
            proc.wait(timeout=5)
        with self.assertRaises(OSError):
            o.identity(proc.pid)


if __name__ == "__main__":
    unittest.main()
