import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from warden import core, linux, storage
from warden.cli import demo, main
from warden.tui import overview, page_lines


def sample(ts=100000, mono=1000, rx=100, tx=200, boot="test-boot"):
    data = demo()
    data.update(timestamp=ts, monotonic=mono, boot=boot)
    data["warnings"] = []
    data["tunnels"] = data["tunnels"][:1]
    data["tunnels"][0].update(rx=rx, tx=tx, peers=[])
    return data


class CoreTests(unittest.TestCase):
    def test_v1_is_parsed_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "controller.py"
            marker = Path(directory) / "should-not-exist"
            source.write_text(f"open({str(marker)!r}, 'w').write('bad')\nVERSION=1\nPATHS={{'primary': {{'if':'awgfp1','local':'10.90.0.2','peer':'10.90.0.1','public':'192.0.2.10'}}}}\n")
            cfg = dict(core.DEFAULTS, engine=str(source), registry=str(Path(directory)/"missing"))
            version, rows = core.channels(cfg)
            self.assertEqual(version, "controller-v1")
            self.assertIsNone(rows[0]["rank"])
            self.assertFalse(marker.exists())

    def test_dynamic_paths_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"controller.py"
            source.write_text("VERSION=1\nPATHS=dict()\n")
            with self.assertRaises(ValueError):
                core.channels(dict(core.DEFAULTS, engine=str(source), registry=str(source)+".missing"))

    def test_registry_flags_and_unique_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"channels.json"
            channel = dict(id="new", name="New", **{"if": "awgfp2"}, local="10.90.2.2", peer="10.90.2.1", public="192.0.2.30", enabled=False, rank=10)
            path.write_text(json.dumps({"version": 2, "channels": [channel]}))
            cfg = dict(core.DEFAULTS, registry=str(path))
            self.assertFalse(core.channels(cfg)[1][0]["enabled"])
            path.write_text(json.dumps({"version": 2, "channels": [channel, channel]}))
            with self.assertRaises(ValueError):
                core.channels(cfg)

    def test_controller_monotonic_boot_and_freshness(self):
        state = {"boot": "abc", "checked_at": 10}
        self.assertTrue(core.controller_state(state, "abc", 20)["fresh"])
        for boot, now in (("other", 20), ("abc", 41), ("abc", 9)):
            self.assertFalse(core.controller_state(state, boot, now)["fresh"])

    def test_kernel_route_wins(self):
        paths = [{"id":"primary","interface":"awgfp1","peer":"10.90.0.1"}]
        rows = [{"dst":"default","dev":"awgfp1","gateway":"10.90.0.1"}, {"dst":"default","type":"unreachable"}]
        self.assertEqual(core.active_route(rows, paths), "primary")
        self.assertEqual(core.active_route(rows+rows[:1], paths), "unknown")
        self.assertEqual(core.active_route(rows[1:], paths), "none")

    def test_active_degraded_and_stale(self):
        state = {"healthy":{"primary":False},"paths":{"primary":{"failures":1}}}
        self.assertEqual(core.channel_health("primary", True, True, state)[0], "Degraded")
        state["paths"]["primary"]["failures"] = 3
        self.assertEqual(core.channel_health("primary", True, True, state)[0], "Down")
        self.assertEqual(core.channel_health("primary", True, False, state)[0], "Unknown")

    def test_peer_without_handshake_does_not_hide_other_peer(self):
        rows = core.parse_peers({"latest-handshakes": "awg0 KEY_A 123\nawg0 KEY_B 0\n",
                                "transfer": "awg0 KEY_A 10 20\nawg0 KEY_B 0 0\n",
                                "allowed-ips": "awg0 KEY_A 10.90.0.1/32,192.0.2.0/24\n"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["handshake"], 123)
        self.assertEqual(rows[1]["handshake"], 0)
        self.assertEqual(len(rows[0]["allowed_ips"]), 2)
        self.assertNotIn("KEY_A", json.dumps(rows))

    def test_oneshot_not_a_failure(self):
        row = {"Type":"oneshot","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","ExecMainExitTimestampMonotonic":"123"}
        self.assertEqual(core.service_state(row), "Idle (last run OK)")
        row["Result"] = "exit-code"
        self.assertEqual(core.service_state(row), "Failed")

    def test_vless_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"vless.json"
            path.write_text(json.dumps({"inbounds":[{"type":"vless","users":[{"uuid":"VERY_SECRET"}],"transport":{"type":"ws","path":"SECRET_PATH"}}], "outbounds":[{"type":"direct","inet4_bind_address":"10.78.254.2","routing_mark":40960}]}))
            result = core.vless_summary(path)
            self.assertEqual(result["users"], 1)
            self.assertNotIn("SECRET", json.dumps(result))


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"state.sqlite3"
        self.store = storage.Store(self.path)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_rate_and_coverage(self):
        self.store.save(sample())
        next_sample = sample(100010, 1010, 1100, 2200)
        self.store.save(next_sample)
        self.assertEqual(next_sample["tunnels"][0]["rx_bps"], 800)
        self.assertEqual(next_sample["tunnels"][0]["active_observed_seconds"], 10)
        result = storage.traffic(self.path, "secondary", 100010, 60)
        self.assertEqual(result["rx_bytes"], 1000)
        self.assertEqual(result["tx_bytes"], 2000)
        self.assertAlmostEqual(result["coverage_percent"], 16.67)

    def test_window_boundary_is_labeled_estimated(self):
        self.store.save(sample())
        self.store.save(sample(100010, 1010, 1100, 2200))
        result = storage.traffic(self.path, "secondary", 100010, 5)
        self.assertEqual(result["rx_bytes"], 500)
        self.assertTrue(result["boundary_estimated"])

    def test_counter_reset_not_giant_spike(self):
        self.store.save(sample(rx=100000))
        data = sample(100010, 1010, 5, 2)
        self.store.save(data)
        self.assertIsNone(data["tunnels"][0]["rx_bps"])
        self.assertIsNone(storage.traffic(self.path, "secondary", 100010, 60)["rx_bytes"])

    def test_gap_boot_and_clock_discontinuity(self):
        baseline = sample()
        for current in (sample(100050,1050), sample(100010,1010,boot="new"), sample(100030,1010)):
            self.assertIsNone(storage.interval(baseline, current))

    def test_generation_change_breaks_rate(self):
        self.store.save(sample())
        data = sample(100010,1010,1100)
        data["tunnels"][0]["generation"] = "replacement"
        self.store.save(data)
        self.assertIsNone(data["tunnels"][0]["rx_bps"])
        self.assertEqual(data["tunnels"][0]["active_observed_seconds"], 0)

    def test_retention_and_reused_database(self):
        self.store.save(sample())
        self.store.event(100000, "test", "secondary", "old")
        self.store.conn.commit()
        self.store.save(sample(100000+core.RETENTION+1,1000+core.RETENTION+1))
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM samples").fetchone()[0], 1)
        self.assertFalse(any(r["detail"] == "old" for r in storage.history(self.path, 0)))

    def test_journal_dedup(self):
        event = {"timestamp":100000,"kind":"controller_switch","entity":"egress","detail":"primary -> secondary","source_id":"cursor-a"}
        self.store.save(sample(), [event], "cursor-a")
        self.store.save(sample(100010,1010), [event], "cursor-a")
        matches = [e for e in storage.history(self.path,0) if e["kind"]=="controller_switch"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(self.store.get("journal_cursor"), "cursor-a")
        self.assertTrue(any(e["kind"]=="controller_switch" for e in storage.history(self.path,0,"primary")))
        self.assertTrue(any(e["kind"]=="controller_switch" for e in storage.history(self.path,0,"secondary")))
        self.assertFalse(storage.history(self.path,0,"other"))

    def test_reader_never_creates_database(self):
        missing = self.path.parent/"missing.sqlite3"
        self.assertIsNone(storage.latest(missing))
        self.assertFalse(missing.exists())

    def test_read_only_connection(self):
        with storage.reader(self.path) as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM samples")

    def test_unknown_schema_refused(self):
        self.store.conn.execute("PRAGMA user_version=99")
        with self.assertRaises(ValueError):
            storage.latest(self.path)

    def test_sqlite_full_rolls_back_snapshot(self):
        self.store.save(sample())
        # Simulate a write failure at the transaction boundary rather than filling disk.
        original = self.store.set
        def fail(key, value):
            if key == "snapshot":
                raise sqlite3.OperationalError("database or disk is full")
            original(key, value)
        with patch.object(self.store,"set",side_effect=fail):
            with self.assertRaises(sqlite3.OperationalError):
                self.store.save(sample(100010,1010,1100))
        self.assertEqual(storage.latest(self.path)["timestamp"],100000)
        self.assertEqual(self.store.conn.execute("SELECT count(*) FROM samples").fetchone()[0],1)

    def test_peer_handshake_events(self):
        a = sample()
        a["tunnels"][0]["peers"] = [demo()["tunnels"][0]["peers"][0]]
        self.store.save(a)
        b = copy.deepcopy(a)
        b.update(timestamp=a["timestamp"]+10,monotonic=a["monotonic"]+10)
        b["tunnels"][0]["peers"][0]["handshake"] += 10
        self.store.save(b)
        self.assertTrue(any(e["kind"] == "handshake_observed" for e in storage.history(self.path,0,"secondary")))


class CollectionTests(unittest.TestCase):
    def test_empty_journal_exit_one_is_successful_empty_read(self):
        for output in ("", "-- No entries --\n"):
            with self.subTest(output=output), patch("warden.linux.subprocess.run", return_value=subprocess.CompletedProcess([],1,output,"")):
                self.assertEqual(linux.command(["journalctl", "--grep=^Protected egress:"]), "")
                # No --grep now: exit 1 is an error, not a clean empty query.
                self.assertFalse(linux.journal_events()[2])

    def test_empty_journal_after_cursor_does_not_trigger_recovery(self):
        with patch("warden.linux.subprocess.run", return_value=subprocess.CompletedProcess([],0,"","")) as run:
            events,cursor,complete = linux.journal_events("cursor-a")
        self.assertEqual(events,[])
        self.assertEqual(cursor,"cursor-a")
        self.assertTrue(complete)
        self.assertEqual(run.call_count,1)

    def test_real_journal_errors_are_not_hidden(self):
        for code,output,error in ((1,"","Permission denied"), (1,"","Failed to seek to cursor"),
                                  (1,"unexpected output",""), (2,"",""), (1,"-- No entries --","Warning: incomplete journal")):
            with self.subTest(code=code,output=output,error=error), patch("warden.linux.subprocess.run", return_value=subprocess.CompletedProcess([],code,output,error)):
                self.assertFalse(linux.journal_events()[2])

    def test_exit_one_normalization_is_journal_grep_only(self):
        with patch("warden.linux.subprocess.run", return_value=subprocess.CompletedProcess([],1,"","")):
            self.assertIsNone(linux.command(["awg","show","interfaces"]))
            self.assertIsNone(linux.command(["journalctl","--no-pager"]))

    def test_journal_timeout_remains_unavailable(self):
        with patch("warden.linux.subprocess.run", side_effect=subprocess.TimeoutExpired("journalctl",3)):
            self.assertFalse(linux.journal_events()[2])

    @unittest.skipUnless(sys.platform=="linux","Linux journalctl integration")
    def test_real_journal_with_no_matching_events(self):
        import shutil
        import uuid
        if not shutil.which("journalctl"):
            self.skipTest("journalctl unavailable")
        argv = ["journalctl","--no-pager","-o","json","--since","1 second ago",
                "--grep=^WARDEN_NO_MATCH_"+uuid.uuid4().hex+"$","-n","1"]
        result = subprocess.run(argv,capture_output=True,text=True,timeout=5,env=dict(os.environ,LC_ALL="C"))
        if result.stderr.strip():
            self.skipTest("This runner has no readable journal; error handling covered separately")
        self.assertIn(result.returncode,(0,1))
        self.assertEqual(linux.command(argv).strip(),"")

    def test_partial_failure_and_no_mutating_commands(self):
        calls = []
        def runner(argv):
            calls.append(argv)
            return None
        with patch("warden.linux.channels", side_effect=ValueError), patch("warden.linux.read_json", side_effect=OSError):
            result = linux.collect(core.DEFAULTS, runner=runner)
        self.assertEqual(result["controller"]["active"], "unknown")
        self.assertTrue(result["warnings"])
        for argv in calls:
            self.assertNotIn("dump", argv)
            self.assertFalse({"apply","sync","start","stop","restart","reload","set","add","del","private-key","preshared-keys"} & set(argv))

    def test_passive_channel_with_kernel_route(self):
        path = {"id":"primary","interface":"awgfp1","peer":"10.90.0.1","local":"10.90.0.2","public":"192.0.2.10","enabled":True,"name":"Primary"}
        health = {"boot":"b","checked_at":90,"healthy":{"primary":False},"paths":{"primary":{"failures":1}},"active":"primary"}
        def runner(argv):
            if argv[:4] == ["ip","-j","-s","link"]:
                return json.dumps([{"ifname":"awgfp1","ifindex":3,"stats64":{"rx":{"bytes":10},"tx":{"bytes":20}}}])
            if "route" in argv:
                return json.dumps([{"dst":"default","dev":"awgfp1","gateway":"10.90.0.1"},{"dst":"default","type":"unreachable"}])
            if "rule" in argv:
                return json.dumps([{"priority":99,"iif":"lo","src":"10.78.254.2","table":10400}])
            if argv==["awg","show","interfaces"]:
                return "awgfp1"
            return ""
        with patch("warden.linux.channels", return_value=("controller-v1",[path])), patch("warden.linux.read_json",return_value=health), patch("warden.linux.read_text",return_value="b"), patch("warden.linux.vless_summary",return_value={"listeners":[]}):
            result = linux.collect(core.DEFAULTS,runner=runner,clock=lambda:1000,monotonic=lambda:100)
        self.assertEqual(result["tunnels"][0]["role"], "Active")
        self.assertEqual(result["tunnels"][0]["health"], "Degraded")

    def test_journal_only_safe_message(self):
        lines = [json.dumps({"MESSAGE":"Protected egress: primary -> secondary","__CURSOR":"abc","__REALTIME_TIMESTAMP":"1000000"}),
                 json.dumps({"MESSAGE":"token=SECRET","__CURSOR":"def","__REALTIME_TIMESTAMP":"2000000"})]
        events,cursor,complete = linux.journal_events(runner=lambda argv:"\n".join(lines))
        self.assertEqual(cursor,"def")
        self.assertTrue(complete)
        self.assertEqual(len(events),1)
        self.assertNotIn("SECRET",json.dumps(events))

    def test_rotated_cursor_recovers_with_dedup_source_id(self):
        output = json.dumps({"MESSAGE":"Protected egress: primary -> secondary","__CURSOR":"new","__REALTIME_TIMESTAMP":"1000000"})
        info = {}
        with patch("warden.linux.subprocess.run", side_effect=[subprocess.CompletedProcess([],1,"","Failed to seek to cursor"), subprocess.CompletedProcess([],0,output,"")]) as run:
            events,cursor,complete = linux.journal_events("old",diagnostics=info)
        self.assertEqual(cursor,"new")
        self.assertTrue(complete)
        self.assertTrue(info["cursor_recovered"])
        self.assertEqual(len(events),1)
        self.assertIn("--since",run.call_args_list[1].args[0])

    def test_empty_journal_uses_recent_window(self):
        calls=[]
        linux.journal_events(runner=lambda args:calls.append(args) or "",since=100000,clock=lambda:100010)
        self.assertEqual(calls[0][-1],"@100000")


class InterfaceTests(unittest.TestCase):
    def test_demo_json_and_aliases(self):
        for name in ("status","-status","list","-list"):
            result = subprocess.run([sys.executable,"-B","-m","warden","--demo",name,"--json"],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)["schema_version"],1)

    def test_no_history_does_not_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"absent.sqlite3"
            with patch("sys.stderr"):
                self.assertEqual(main(["--database",str(path),"history"]),2)
            self.assertFalse(path.exists())

    def test_all_screens_format(self):
        data = demo()
        for tab in range(6):
            self.assertTrue(page_lines(data,tab,0,core.DEFAULTS,demo_mode=True))
        self.assertTrue(page_lines(data,1,0,core.DEFAULTS,detail=True))
        self.assertIn("READ ONLY",overview(data)[0])

    @unittest.skipUnless(sys.platform=="linux","Linux curses/PTY integration")
    def test_real_curses_navigation_and_resize(self):
        import fcntl
        import pty
        import struct
        import termios
        import time
        master,slave = pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack("HHHH",30,120,0,0))
        process = subprocess.Popen([sys.executable,"-B","-m","warden","--demo","tui"],stdin=slave,stdout=slave,stderr=slave,env=dict(os.environ,TERM="xterm-256color"))
        os.close(slave)
        try:
            time.sleep(0.5)
            os.write(master,b"2\r\x1b3456")
            fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack("HHHH",6,40,0,0))
            time.sleep(0.3)
            os.write(master,b"q")
            process.wait(timeout=8)
            output = bytearray()
            while True:
                try:
                    chunk = os.read(master,65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
            self.assertEqual(process.returncode,0,output.decode(errors="replace"))
            self.assertNotIn(b"Traceback",output)
            self.assertIn(b"WARDEN",output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)


if __name__ == "__main__":
    unittest.main()
