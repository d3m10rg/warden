import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch, Mock

from warden import channel_admin as a, core
from warden.cli import main


class PriorityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/"channels.json"
        self.rows = [dict(id="primary", **{"if": "awgfp2"}, peer="10.90.0.1", local="10.90.0.2",
                          public="192.0.2.1", rank=10, enabled=True),
                     dict(id="secondary", **{"if": "awgfp0"}, peer="10.90.1.1", local="10.90.1.2",
                          public="192.0.2.2", rank=20, enabled=True)]
        self.save()
        self.cfg = dict(core.DEFAULTS, registry=str(self.path))
        self.default = patch.dict(core.DEFAULTS, registry=str(self.path))
        self.default.start()
        self.addCleanup(self.default.stop)

    def save(self):
        self.path.write_text(json.dumps({"version": 2, "channels": self.rows}))

    def test_preview_is_passive_and_cli_demo_refuses(self):
        with patch("warden.cli.config", return_value=self.cfg), patch.object(a, "start") as start:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["priority", "primary", "15"]), 0)
            self.assertIn("PREVIEW ONLY", output.getvalue())
            start.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--demo", "priority", "primary", "15", "--run"]), 2)

    def test_conflicts_permanent_disabled_retired_and_bad_rank_refused(self):
        for entity, rank in (("primary", 20), ("awg0", 15), ("primary", 0), ("primary", True), ("primary", 2147483648)):
            with self.subTest(entity=entity, rank=rank), self.assertRaises(ValueError):
                a.plan(self.cfg, entity, rank)
        for change in ({"enabled": False}, {"retired": True}):
            self.rows[0].update(change)
            self.save()
            with self.assertRaises(ValueError):
                a.plan(self.cfg, "primary", 15)

    def test_registry_drift_prevents_execution(self):
        p = a.plan(self.cfg, "primary", 15)
        self.rows[0]["if"] = "awgfp9"
        self.save()
        with self.assertRaisesRegex(ValueError, "changed"):
            a.backend(self.cfg, p)

    def test_backend_preserves_ssh_and_delegates_only_priority(self):
        p = a.plan(self.cfg, "primary", 15)
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "geteuid", return_value=0, create=True), \
             patch.object(a.Path, "is_file", return_value=True), patch.object(a.os, "access", return_value=True), \
             patch.dict(os.environ, SSH_CONNECTION="192.0.2.99 1234 192.0.2.10 22"):
            argv, env = a.backend(self.cfg, p)
            self.assertEqual(argv, [a.CTL, "set-priority", "--id", "primary", "--priority", "15", "--apply"])
            self.assertEqual(env["SSH_CONNECTION"], os.environ["SSH_CONNECTION"])
            with patch.dict(os.environ, SSH_CONNECTION=""):
                with self.assertRaisesRegex(ValueError, "SSH_CONNECTION"):
                    a.backend(self.cfg, p)

    def test_ui_confirm_cancel_and_inflight_protection(self):
        view = a.PriorityView(self.cfg, "primary")
        with patch.object(a, "backend"), patch.object(a, "start") as start:
            view.handle("1")
            view.handle("5")
            view.handle("ENTER")
            self.assertEqual(view.mode, "confirm")
            start.assert_not_called()
            self.assertIn("10 -> 15", " ".join(view.render(80)))
            view.handle("n")
            self.assertEqual(view.mode, "closed")
            view = a.PriorityView(self.cfg, "primary")
            for key in ("1", "5", "ENTER", "y"):
                view.handle(key)
            start.assert_called_once()
            self.assertTrue(view.handle("q"))
            self.assertEqual(view.mode, "running")
            start.return_value.done.return_value = True
            start.return_value.result.return_value = ["Backend manifest: test"]
            view.poll()
            self.assertEqual(view.mode, "result")

    def test_custom_registry_is_not_applied_to_production(self):
        with self.assertRaisesRegex(ValueError, "standard"):
            a.plan(dict(self.cfg, registry="/tmp/other.json"), "primary", 15)

    @unittest.skipUnless(sys.platform == "linux", "Linux curses priority workflow")
    def test_real_priority_form_confirmation_and_result(self):
        import fcntl
        import pty
        import select
        import struct
        import termios
        import time
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        code = ("import sys,os; from warden import channel_admin as a; from warden.tui import run; "
                "from warden.cli import demo; from warden.core import DEFAULTS; "
                "a.plan=lambda cfg,e,r:dict(id=e,interface='awgfp0',old_rank=10,rank=r); "
                "a.backend=lambda *args:([sys.executable,'-c',\"import time; time.sleep(0.8); print('TEST-PRIORITY-DONE')\"],dict(os.environ)); "
                "run(demo(),dict(DEFAULTS,database=sys.argv[1]))")
        proc = subprocess.Popen([sys.executable, "-B", "-c", code, str(self.path)+".db"],
                                stdin=slave, stdout=slave, stderr=slave, env=dict(os.environ, TERM="xterm-256color"))
        os.close(slave)
        output = bytearray()
        def until(marker):
            end = time.monotonic()+8
            while marker not in output and time.monotonic() < end:
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            self.assertIn(marker, output, output.decode(errors="replace"))
        try:
            until(b"WARDEN")
            os.write(master, b"2p")
            until(b"New priority:")
            os.write(master, b"15\r")
            until(b"y: apply | n/Esc: cancel")
            os.write(master, b"y")
            until(b"RUNNING")
            os.write(master, b"q1")  # Running transaction cannot be left/cancelled.
            until(b"TEST-PRIORITY-DONE")
            os.write(master, b"n")
            time.sleep(0.2)
            os.write(master, b"q")
            proc.wait(timeout=8)
            self.assertEqual(proc.returncode, 0)
            self.assertNotIn(b"Traceback", output)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
