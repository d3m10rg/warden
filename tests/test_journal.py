"""Journal progress and bounded work, including real Linux journalctl ordering."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from warden import linux
from warden.cli import demo
from warden.diagnostics import doctor
from warden.storage import Store, latest, history


def record(i, switch=False):
    return json.dumps({"__CURSOR": "c"+str(i), "__REALTIME_TIMESTAMP": str((100000+i)*1000000),
                       "MESSAGE": "Protected egress: primary -> secondary" if switch else "PRIVATE ignored message"})


class JournalTests(unittest.TestCase):
    def test_first_page_advances_past_non_switch_messages(self):
        calls, info = [], {}
        def runner(args):
            calls.append(args)
            start = int(args[-1][1:])+1 if "--after-cursor" in args else 0
            return "\n".join(record(i, i in (30, 510)) for i in range(start, min(start+500, 550)))
        first, cursor, complete = linux.journal_events(runner=runner, diagnostics=info, clock=lambda:101000)
        self.assertFalse(complete)
        self.assertEqual(cursor, "c499")
        self.assertEqual(info["status"], "Catching up")
        second, cursor, complete = linux.journal_events(cursor, runner, diagnostics=info, clock=lambda:101000)
        self.assertTrue(complete)
        self.assertEqual(cursor, "c549")
        self.assertEqual([e["source_id"] for e in first+second], ["c30", "c510"])
        self.assertNotIn("PRIVATE", json.dumps(first+second+list(info.values())))
        for argv in calls:
            self.assertIn("+500", argv)
            self.assertFalse(any(a.startswith("--grep") for a in argv))
            self.assertNotIn("--reverse", argv)

    def test_quiet_service_uses_time_checkpoint_when_no_cursor(self):
        calls, info = [], {}
        linux.journal_events(runner=lambda a: calls.append(a) or "", diagnostics=info, clock=lambda:200000)
        self.assertEqual(info["watermark"], 199998)
        linux.journal_events(since=info["watermark"], runner=lambda a: calls.append(a) or "", clock=lambda:200010)
        self.assertEqual(calls[-1][-1], "@199998")

    def test_old_or_future_checkpoint_resets_to_retention_window(self):
        for since in (1, 1000001):
            calls = []
            linux.journal_events("old", since=since, runner=lambda a: calls.append(a) or "", clock=lambda:1000000)
            self.assertNotIn("--after-cursor", calls[0])
            self.assertIn("--since", calls[0])

    def test_timeout_does_not_fall_back_to_another_scan(self):
        info = {}
        with patch("warden.linux.subprocess.run", side_effect=subprocess.TimeoutExpired("journalctl", 3)) as run:
            self.assertFalse(linux.journal_events("old", diagnostics=info)[2])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(info["error"], "timeout (3s)")

    def test_empty_rotated_cursor_is_cleared(self):
        results = [subprocess.CompletedProcess([], 1, "", "Failed to seek to cursor"),
                   subprocess.CompletedProcess([], 0, "", "")]
        info = {}
        with patch("warden.linux.subprocess.run", side_effect=results):
            events, cursor, complete = linux.journal_events("old", diagnostics=info)
        self.assertTrue(complete)
        self.assertEqual(cursor, "")
        self.assertTrue(info["cursor_recovered"])

    def test_invalid_entry_never_advances_past_it(self):
        info = {}
        output = record(0, True) + "\n{}\n" + record(2, True)
        events, cursor, complete = linux.journal_events(runner=lambda a:output, diagnostics=info)
        self.assertFalse(complete)
        self.assertEqual(cursor, "c0")
        self.assertEqual(len(events), 1)
        self.assertEqual(info["error"], "invalid journal entry")

    def test_retry_backoff_leaves_observations_running(self):
        poller = linux.JournalPoller()
        calls = []
        now = [100]
        def reader(cursor, since, diagnostics):
            calls.append(cursor)
            diagnostics.update(reader_version=2, status="Error", error="timeout (3s)")
            return [], cursor, False
        for t in (100, 110, 120, 150, 160, 170, 200):
            now[0] = t
            poller.poll("saved", None, reader=reader, monotonic=lambda:now[0])
        self.assertEqual(len(calls), 2)
        self.assertEqual(poller.retry_at, 280)
        self.assertIn("retry in", poller.warning())
        def success(cursor, since, diagnostics):
            diagnostics.update(status="Ready", error=None, watermark=50)
            return [], cursor, True
        now[0] = 280
        self.assertEqual(poller.poll("saved", None, reader=success, monotonic=lambda:now[0])[2], 50)
        self.assertEqual(poller.failures, 0)
        self.assertIsNone(poller.warning())

    def test_upgrade_resets_old_cursor_once_and_preserves_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"state.sqlite3"
            s = Store(path)
            try:
                value = demo()
                s.save(value, [dict(timestamp=value["timestamp"],kind="controller_switch",entity="egress",detail="primary -> secondary",source_id="kept")], "old", 20)
                value["journal"] = {"reader_version": 2, "status": "Error", "error": "timeout (3s)"}
                s.save(value)
                self.assertIsNone(s.get("journal_cursor"))
                self.assertIsNone(s.get("journal_since"))
                self.assertEqual(s.get("journal_reader_version"), 2)
                s.save(value, cursor="new", journal_since=30)
                s.save(value)
                self.assertEqual(s.get("journal_cursor"), "new")
                self.assertEqual(len([e for e in history(path, value["timestamp"]-1) if e["kind"] == "controller_switch"]), 1)
            finally:
                s.close()

    def test_doctor_distinguishes_live_observations_and_saved_journal(self):
        value = demo()
        value["warnings"] = []
        saved = demo()
        saved["timestamp"] -= 60
        saved["journal"] = {"status":"Error", "error":"timeout (3s)", "records":0, "cursor":"PRIVATE"}
        result = doctor(value, saved)
        self.assertEqual(result["observation_warnings"], 0)
        self.assertEqual(result["collector_journal"]["status"], "Error")
        self.assertGreaterEqual(result["collector_journal"]["snapshot_age_seconds"], 60)
        self.assertNotIn("PRIVATE", json.dumps(result))


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "Root Linux journal integration")
class RealJournalTests(unittest.TestCase):
    def test_forward_pages_against_real_journald(self):
        if not shutil.which("systemd-run") or not Path("/run/systemd/system").exists():
            self.skipTest("systemd unavailable")
        unit = "warden-test-" + uuid.uuid4().hex + ".service"
        code = "for i in range(550): print('Protected egress: primary -> secondary' if i in (30,510) else 'PRIVATE ignored '+str(i), flush=True)"
        subprocess.run(["systemd-run", "--quiet", "--wait", "--collect", "--unit="+unit,
                        "--property=StandardOutput=journal", "--property=StandardError=journal",
                        sys.executable, "-u", "-c", code], check=True, capture_output=True, timeout=30)
        def runner(argv):
            argv = list(argv)
            argv[argv.index("-u")+1] = unit
            return linux.command(argv)
        info = {}
        first, cursor, complete = linux.journal_events(runner=runner, diagnostics=info)
        self.assertFalse(complete, info)
        self.assertEqual(info["records"], 500)
        self.assertEqual(len(first), 1)
        second, cursor, complete = linux.journal_events(cursor, runner=runner, diagnostics=info)
        self.assertTrue(complete, info)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first[0]["source_id"], second[0]["source_id"])
        third, _, complete = linux.journal_events(cursor, runner=runner, diagnostics=info)
        self.assertTrue(complete, info)
        self.assertEqual(third, [])


if __name__ == "__main__":
    unittest.main()
