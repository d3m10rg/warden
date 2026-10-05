import copy
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from warden import core, diagnostics as d
from warden.cli import demo, main
from warden.tui import frame, page_lines


def data():
    value = demo()
    value["tunnels"] = value["tunnels"][:1]
    value["tunnels"][0].update(local="10.90.0.2", peer="10.90.0.1", public="192.0.2.20", table=10411, mark=66577)
    return value


def route(argv):
    if "show" in argv:
        return json.dumps([{"dst": "default", "type": "unreachable"}])
    return json.dumps([{"dev": "awgfp0", "prefsrc": "10.90.0.2", "table": 10411}])


CONSTANTS = {"SOURCE": "10.90.254.2", "TARGETS": (("192.0.2.100", "example.org", "/health"),)}


class DiagnosticTests(unittest.TestCase):
    def test_internal_route_and_local_source(self):
        calls = []
        p = d.plan(data(), core.DEFAULTS, "secondary", "internal", runner=lambda args: calls.append(args) or route(args))
        self.assertEqual(p["target"], "10.90.0.1")
        self.assertEqual(p["source"], "10.90.0.2")
        self.assertTrue(all("from" in c and "oif" in c for c in calls))

    def test_wrong_or_unknown_route_refuses(self):
        for response in (None, "[]", '[{"dev":"eth0"}]', '[{"type":"unreachable"}]', '[{},{}]'):
            with self.subTest(response=response), self.assertRaises(ValueError):
                d.plan(data(), core.DEFAULTS, "secondary", "internal", runner=lambda args: response)

    def test_https_guards_and_tuple(self):
        with patch.object(d, "controller_literals", return_value=CONSTANTS):
            p = d.plan(data(), core.DEFAULTS, "secondary", "https", runner=route)
            self.assertEqual((p["source"], p["table"], p["mark"]), ("10.90.254.2", 10411, 66577))
            for response in ('[{"dev":"awgfp0","table":254}]', '[{"dev":"awgfp0","table":10411}]'):
                with self.assertRaises(ValueError):
                    d.plan(data(), core.DEFAULTS, "secondary", "https", runner=lambda args: response)

    def test_stale_and_missing_metadata_refuse(self):
        stale = data()
        stale["timestamp"] -= 60
        with self.assertRaises(ValueError):
            d.plan(stale, core.DEFAULTS, "secondary", "internal", runner=route)
        for field in ("table", "mark"):
            value = data()
            value["tunnels"][0][field] = None
            with patch.object(d, "controller_literals", return_value=CONSTANTS), self.assertRaises(ValueError):
                d.plan(value, core.DEFAULTS, "secondary", "https", runner=route)

    def test_external_refuses_tunnel_and_pins_wan(self):
        with self.assertRaises(ValueError):
            d.plan(data(), core.DEFAULTS, "secondary", "external", runner=route)
        p = d.plan(data(), core.DEFAULTS, "secondary", "external",
                   runner=lambda args: '[{"dev":"eth0","prefsrc":"192.0.2.1"}]')
        self.assertEqual(p["interface"], "eth0")
        self.assertEqual(p["source"], "192.0.2.1")

    def test_source_inference_is_rechecked(self):
        value = data()
        value["tunnels"][0].pop("local")
        def runner(args):
            return '[{"dev":"eth0"}]' if "from" in args else route(args)
        with self.assertRaises(ValueError):
            d.plan(value, core.DEFAULTS, "secondary", "internal", runner=runner)

    def test_permanent_targets_explicit_and_no_failover(self):
        value = data()
        row = value["tunnels"][0]
        row.update(id="site", kind="Permanent / unmanaged")
        row.pop("peer")
        with self.assertRaisesRegex(ValueError, "Configure"):
            d.plan(value, core.DEFAULTS, "site", "internal", runner=route)
        cfg = dict(core.DEFAULTS, diagnostics={"site": {"internal": "10.90.0.1"}})
        self.assertEqual(d.plan(value, cfg, "site", "internal", runner=route)["target"], "10.90.0.1")
        with self.assertRaises(ValueError):
            d.plan(value, cfg, "site", "https", runner=route)

    def test_config_rejects_names_injection_and_unbounded_options(self):
        for ip in ("example.org", "1.2.3.4;reboot", "127.0.0.1", "::1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                d.validate_config({"site": {"internal": ip}})
        for item in ({"speed_port": 0}, {"speed_port": True}, {"seconds": 100}, {"command": "reboot"}):
            with self.assertRaises(ValueError):
                d.validate_config({"site": item})

    def test_speed_needs_target_and_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "speed_host"):
            d.plan(data(), core.DEFAULTS, "secondary", "speed", runner=route)
        cfg = dict(core.DEFAULTS, diagnostics={"secondary": {"speed_host": "10.90.0.1"}})
        for seconds, mbps in ((0, 5), (11, 5), (5, 0), (5, 11), (True, 5)):
            with self.assertRaises(ValueError):
                d.plan(data(), cfg, "secondary", "speed", seconds, mbps, runner=route)
        p = d.plan(data(), cfg, "secondary", "speed", reverse=True, runner=route)
        with patch.object(d, "subprocess_probe", return_value=(0, '{"end":{"sum_received":{"bits_per_second":4000000},"sum_sent":{"bits_per_second":4100000}}}', "")) as run:
            result = d.execute(p)
        argv, timeout = run.call_args.args
        self.assertIn("--bind-dev", argv)
        self.assertIn("-R", argv)
        self.assertEqual(argv[argv.index("-b")+1], "5000000")
        self.assertEqual(argv[argv.index("-P")+1], "1")
        self.assertEqual(timeout, 10)
        self.assertEqual(result["direction"], "download")
        self.assertEqual(result["received_bps"], 4000000)

    def test_ping_reply_loss_and_error_are_distinct(self):
        p = d.plan(data(), core.DEFAULTS, "secondary", "internal", runner=route)
        for code, output, err, expected in (
            (0, "3 packets transmitted, 3 received\nrtt min/avg/max/mdev = 1.0/2.0/3.0/0.5 ms", "", "Reachable"),
            (1, "3 packets transmitted, 1 received", "", "Reachable"),
            (1, "3 packets transmitted, 0 received", "", "No reply"),
            (2, "", "not permitted", "Error")):
            with patch.object(d, "subprocess_probe", return_value=(code, output, err)):
                result = d.execute(p)
            self.assertEqual(result["status"], expected)
            self.assertNotIn("Unreachable", result["status"])

    def test_tls_binds_before_connect_and_verifies_certificate(self):
        with patch.object(d, "controller_literals", return_value=CONSTANTS):
            p = d.plan(data(), core.DEFAULTS, "secondary", "https", runner=route)
        raw = MagicMock()
        raw.__enter__.return_value = raw
        tls = MagicMock()
        tls.__enter__.return_value = tls
        tls.recv.return_value = b"HTTP/1.1 200 OK\r\nSECRET RESPONSE"
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        with patch.object(socket, "SO_BINDTODEVICE", 25, create=True), patch.object(socket, "SO_MARK", 36, create=True), patch.object(d.socket, "socket", return_value=raw), patch.object(d.ssl, "create_default_context", return_value=ctx):
            result = d.execute(p)
        self.assertEqual(result["status"], "Passed")
        names = [c[0] for c in raw.method_calls]
        self.assertLess(names.index("setsockopt"), names.index("connect"))
        self.assertLess(names.index("bind"), names.index("connect"))
        self.assertEqual(ctx.wrap_socket.call_args.kwargs["server_hostname"], "example.org")
        self.assertNotIn("SECRET RESPONSE", json.dumps(result))

    def test_bind_failure_never_connects(self):
        raw = MagicMock()
        raw.__enter__.return_value = raw
        raw.setsockopt.side_effect = PermissionError()
        p = dict(interface="awgfp0", source="10.90.0.2", target="192.0.2.100", mark=66577, kind="https")
        with patch.object(socket, "SO_BINDTODEVICE", 25, create=True), patch.object(d.socket, "socket", return_value=raw):
            result = d.execute(p)
        self.assertEqual(result["status"], "Error")
        raw.connect.assert_not_called()

    def test_report_drops_all_sensitive_values(self):
        value = data()
        value["warnings"] = ["secret warning"]
        value["vless"] = {"uuid": "secret credential"}
        report = json.dumps(d.doctor(value))
        for forbidden in ("192.0.2", "10.90", "secret", "demo-peer", "Forpost"):
            self.assertNotIn(forbidden, report)

    def test_cli_preview_never_executes(self):
        with patch("warden.cli.sys.platform", "linux"), patch("warden.cli.signal.signal"), patch("warden.cli.collect", return_value=data()), patch.object(d, "diagnostic_lock"), patch.object(d, "plan", return_value={"entity": "secondary"}), patch.object(d, "execute") as execute, patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(["ping", "secondary", "--json"]), 0)
            execute.assert_not_called()

    def test_changed_plan_rejects_tui_confirmation(self):
        with patch("warden.cli.sys.platform", "linux"), patch("warden.cli.signal.signal"), patch("warden.cli.collect", return_value=data()), patch.object(d, "diagnostic_lock"), patch.object(d, "plan", return_value={"target": "192.0.2.2"}), patch.object(d, "execute") as execute, patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(["ping", "secondary", "--run", "--expect-plan", '{"target":"192.0.2.1"}']), 2)
            execute.assert_not_called()

    def test_subprocess_timeout_kills_and_reaps(self):
        proc = MagicMock()
        proc.__enter__.return_value = proc
        proc.communicate.side_effect = [subprocess.TimeoutExpired("ping", 1), ("", "")]
        with patch.object(d.subprocess, "Popen", return_value=proc), self.assertRaises(subprocess.TimeoutExpired):
            d.subprocess_probe(["ping"], 1)
        proc.kill.assert_called_once()
        self.assertEqual(proc.communicate.call_count, 2)

    def test_frame_dimensions_and_all_tabs(self):
        value = data()
        for width, height in ((60, 16), (79, 24), (119, 40), (180, 50)):
            for tab in range(7):
                rows = page_lines(value, tab, 0, core.DEFAULTS, demo_mode=True, width=width)
                output = frame(value, rows, width, height, tab)
                self.assertEqual(len(output), height)
                self.assertTrue(all(len(line) <= width for line in output))
                self.assertTrue(output[0].startswith("+- WARDEN"))
                self.assertTrue(output[-1].startswith("+---"))
        self.assertIn("enlarge", frame(value, [], 40, 6, 0)[0])


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "Root Linux isolated network namespace test")
class LinuxRouteTests(unittest.TestCase):
    def test_real_kernel_mark_table_guard_and_bound_ping(self):
        if not shutil.which("ip") or not shutil.which("ping"):
            self.skipTest("iproute2/iputils unavailable")
        ns = "warden-test-" + str(os.getpid())
        subprocess.run(["ip", "netns", "add", ns], check=True, capture_output=True)
        def run(*args):
            return subprocess.run(["ip", "netns", "exec", ns, *args], check=True, capture_output=True, text=True)
        def runner(args):
            try:
                return run(*args).stdout
            except subprocess.CalledProcessError:
                return None
        try:
            run("ip", "link", "add", "awgfp0", "type", "dummy")
            run("ip", "addr", "add", "10.90.0.2/30", "dev", "awgfp0")
            run("ip", "link", "set", "awgfp0", "up")
            run("ip", "addr", "add", "10.90.254.2/32", "dev", "lo")
            run("ip", "link", "set", "lo", "up")
            run("ip", "route", "add", "default", "via", "10.90.0.1", "dev", "awgfp0", "onlink", "table", "10411")
            run("ip", "route", "add", "unreachable", "default", "metric", "42760", "table", "10411")
            run("ip", "rule", "add", "from", "10.90.254.2", "fwmark", "66577", "table", "10411")
            with patch.object(d, "controller_literals", return_value=CONSTANTS):
                p = d.plan(data(), core.DEFAULTS, "secondary", "https", runner=runner)
                self.assertEqual(p["table"], 10411)
                run("ip", "route", "del", "unreachable", "default", "metric", "42760", "table", "10411")
                with self.assertRaisesRegex(ValueError, "guard"):
                    d.plan(data(), core.DEFAULTS, "secondary", "https", runner=runner)
            p = d.plan(data(), core.DEFAULTS, "secondary", "internal", runner=runner)
            original = d.subprocess_probe
            with patch.object(d, "subprocess_probe", side_effect=lambda argv, timeout: original(["ip", "netns", "exec", ns, *argv], timeout)):
                result = d.execute(p)
            self.assertEqual(result["status"], "No reply", result)
        finally:
            subprocess.run(["ip", "netns", "del", ns], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
