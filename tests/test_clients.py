import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

from warden import clients, core
from warden.cli import demo, main
from warden.tui import details, page_lines


def fixture():
    return {"inbounds": [{"type": "vless", "tag": "vless-ws", "users": [
        {"name": "alice", "uuid": "PRIVATE-ALICE"}, {"name": "bob", "uuid": "PRIVATE-BOB"}]}],
        "outbounds": [{"type": "direct", "tag": "forpost-vless-user-1",
                       "inet4_bind_address": "10.78.254.2", "routing_mark": 9001},
                      {"type": "direct", "tag": "unrelated"}],
        "route": {"rules": [{"auth_user": ["alice"], "outbound": "forpost-vless-user-1"}]}}


class ClientTests(unittest.TestCase):
    def test_list_and_tab_never_execute_or_disclose_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(fixture()))
            cfg = dict(core.DEFAULTS, vless=str(path))
            output = io.StringIO()
            with patch.object(clients.subprocess, "run") as runner, patch("warden.cli.config", return_value=cfg), contextlib.redirect_stdout(output):
                self.assertEqual(main(["clients", "list", "--json"]), 0)
                page = "\n".join(page_lines(demo(), 7, 0, cfg))
            runner.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["clients"], ["alice", "bob"])
            self.assertNotIn("PRIVATE", output.getvalue() + page)
            self.assertEqual(json.loads(path.read_text()), fixture())

    def test_preview_all_operations_never_executes(self):
        with patch.object(clients, "names", return_value=["alice", "bob"]), patch.object(clients, "execute") as execute:
            for action, name in (("add", "carol"), ("rotate", "alice"), ("remove", "bob"), ("show", "all")):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(main(["--config", "missing-warden-config", "clients", action, name]), 0)
                self.assertIn("PREVIEW ONLY", output.getvalue())
            execute.assert_not_called()

    def test_validation_last_client_duplicate_unknown_and_injection(self):
        with patch.object(clients, "names", return_value=["alice"]):
            for action, name in (("remove", "alice"), ("add", "alice"), ("rotate", "bob"),
                                 ("add", "all"), ("show", "a;touch x"), ("show", "a\nb"), ("add", "x"*65)):
                with self.subTest(action=action, name=name), self.assertRaises(ValueError):
                    clients.preview(core.DEFAULTS, action, name)
            self.assertIn("subscription URL", " ".join(clients.preview(core.DEFAULTS, "rotate", "alice")))
        with self.assertRaisesRegex(ValueError, "standard"):
            clients.preview(dict(core.DEFAULTS, vless="/tmp/other.json"), "show", "alice")

    def test_demo_does_not_read_clients(self):
        with patch.object(clients, "names") as names, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--demo", "clients", "list"]), 2)
            page_lines(demo(), 7, 0, core.DEFAULTS, demo_mode=True)
            names.assert_not_called()

    def test_explicit_run_delegates_once_and_reports_partial_failure(self):
        output = io.StringIO()
        with patch.object(clients, "preview"), patch.object(clients.sys, "platform", "linux"), \
             patch.object(clients.os, "geteuid", return_value=0, create=True), \
             patch.object(clients.Path, "is_file", return_value=True), \
             patch.object(clients.signal, "SIGHUP", 1, create=True), \
             patch.object(clients.signal, "signal") as signal, \
             patch.object(clients.subprocess, "run", return_value=Mock(returncode=1)) as runner, \
             contextlib.redirect_stderr(output):
            self.assertEqual(clients.execute(core.DEFAULTS, "rotate", "alice"), 1)
            runner.assert_called_once()
            args, kwargs = runner.call_args
            self.assertEqual(args[0], ["/bin/sh", str(clients.HELPER), "rotate", "alice"])
            self.assertEqual(kwargs["env"]["VLESS_ENV_FILE"], core.DEFAULTS["clients_env"])
            self.assertNotIn("timeout", kwargs)
            self.assertNotIn("shell", kwargs)
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(signal.call_count, 6)  # handlers restored
        self.assertIn("Some changes may already have applied", output.getvalue())

    def test_clients_view_confirmation_cancel_and_secret_cleanup(self):
        from warden.clients_view import ClientsView
        view = ClientsView(core.DEFAULTS)
        with patch.object(clients, "names", return_value=["alice", "bob"]), \
             patch.object(clients, "backend"), patch.object(clients, "Operation") as operation:
            view.refresh()
            view.handle("DOWN")
            view.handle("d")
            self.assertEqual(view.pending, ("remove", "bob"))
            operation.assert_not_called()
            view.handle("n")
            self.assertEqual(view.mode, "list")
            view.handle("r")
            view.handle("y")
            operation.assert_called_once_with(core.DEFAULTS, "rotate", "bob")
            self.assertEqual(view.mode, "running")
            for key in ("q", "ESC", "1", "y"):
                self.assertTrue(view.handle(key))
            operation.return_value.done.return_value = True
            operation.return_value.result.return_value = ["vless://PRIVATE"]
            view.poll()
            self.assertIn("PRIVATE", " ".join(view.render(80)))
            view.handle("ESC")
            self.assertNotIn("PRIVATE", " ".join(view.render(80)))
            self.assertIsNone(view.pending)

    def test_clients_view_name_input_and_missing_env(self):
        from warden.clients_view import ClientsView
        view = ClientsView(core.DEFAULTS)
        with patch.object(clients, "names", return_value=["alice"]), \
             patch.object(clients, "backend", side_effect=ValueError("Missing VLESS env")), \
             patch.object(clients, "Operation") as operation:
            view.refresh()
            view.handle("a")
            for char in "qa-client":
                view.handle(char)
            self.assertEqual(view.text, "qa-client")
            view.handle("ENTER")
            self.assertEqual(view.mode, "result")
            self.assertIsNone(view.pending)
            view.handle("y")
            operation.assert_not_called()
            self.assertIn("Missing VLESS env", " ".join(view.render(80)))

    def test_operation_captures_output_in_bounded_memory(self):
        with patch.object(clients, "backend", return_value=(
                [sys.executable, "-c", "import sys; sys.stdout.write('x'*300000); sys.stderr.write('done')"], dict(os.environ))):
            job = clients.Operation(core.DEFAULTS, "show", "alice")
            job.wait()
            self.assertTrue(job.done())
            self.assertEqual(job.returncode, 0)
            self.assertEqual(len(job.output), job.LIMIT)
            self.assertTrue(job.truncated)

    def test_operation_progress_arrives_before_child_finishes(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            release = Path(tmp) / "release"
            code = ("import sys,time; from pathlib import Path; print('[WAIT] READY',flush=True); "
                    "release=Path(sys.argv[1]);\nwhile not release.exists(): time.sleep(0.02)\nprint('DONE')")
            job = clients.Operation(core.DEFAULTS, "priority", "test", command=(
                [sys.executable, "-B", "-c", code, str(release)], dict(os.environ)))
            try:
                deadline = time.monotonic()+5
                while not job.progress() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(job.progress(), ["[WAIT] READY"])
                self.assertFalse(job.done())
            finally:
                release.touch()
                job.wait(5)
                if not job.done():
                    job.process.kill()
                    job.wait()
            self.assertEqual(job.result(), ["[WAIT] READY", "DONE"])

    def test_template_env_is_rejected_before_execution(self):
        with patch.object(clients, "preview"), patch.object(clients.sys, "platform", "linux"), \
             patch.object(clients.os, "geteuid", return_value=0, create=True), \
             patch.object(clients.Path, "is_file", return_value=True), \
             patch.object(clients.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "template"):
                clients.Operation(dict(core.DEFAULTS, clients_env="/root/vless.env.example"), "add", "test")
            spawn.assert_not_called()

    def test_long_notice_fits_small_frame_and_clients_page_scrolls(self):
        from warden.tui import frame
        from warden.clients_view import ClientsView
        self.assertEqual(len(frame(demo(), ["test"], 60, 16, 7, message="Very long "*50)), 16)
        view = ClientsView(core.DEFAULTS, demo=True)
        view.users = ["client"+str(i) for i in range(25)]
        view.handle("PGDN")
        self.assertEqual(view.selected, 10)
        view.handle("PGUP")
        self.assertEqual(view.selected, 0)

    def test_controller_details_include_transport_and_tls_failure(self):
        p = core.probe_details({"probe_details": {"primary": [{"target": "192.0.2.1", "stage": "tls",
            "reason": "timeout", "elapsed_ms": 5000, "private": "DO-NOT-COPY"}]}}, "primary")
        row = dict(demo()["tunnels"][0], transport="icmp", rank=10, probe_details=p, probes_fresh=True)
        text = "\n".join(details(row))
        self.assertIn("tls / timeout", text)
        self.assertIn("Transport: icmp", text)
        self.assertNotIn("DO-NOT-COPY", text)
        self.assertNotIn("v1 has fixed", text)

    def test_registry_transports_disabled_and_retired_are_observed(self):
        from warden import linux
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "channels.json"
            channel = {"id": "primary", "if": "awgfp2", "name": "New primary", "enabled": False,
                       "retired": True, "rank": 10, "peer": "10.90.0.1", "local": "10.90.0.2",
                       "public": "192.0.2.1", "transport": {"kind": "icmp", "private": "SECRET"}}
            path.write_text(json.dumps({"version": 2, "channels": [channel]}))
            cfg = dict(core.DEFAULTS, registry=str(path), health=str(path)+".missing", vless=str(path)+".missing")
            calls = []
            def runner(argv):
                calls.append(argv)
                if "link" in argv:
                    return '[{"ifname":"awgfp2","ifindex":2}]'
                return "[]" if "-j" in argv else ""
            data = linux.collect(cfg, runner=runner)
            self.assertEqual(data["tunnels"][0]["transport"], "icmp")
            self.assertEqual(data["tunnels"][0]["role"], "Retired")
            self.assertNotIn("SECRET", json.dumps(data))
            self.assertTrue(any("forpost-faketcp-awgfp2.service" in c for c in calls))

    @unittest.skipUnless(sys.platform == "linux", "Linux curses menu round-trip")
    def test_curses_clients_menu_returns_to_monitor(self):
        import fcntl
        import pty
        import select
        import struct
        import termios
        import time
        with tempfile.TemporaryDirectory() as tmp:
            cfgpath = Path(tmp) / "vless.json"
            cfgpath.write_text(json.dumps(fixture()))
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
            code = ("from warden.tui import run; from warden.cli import demo; from warden.core import DEFAULTS; "
                    "import sys; from warden import clients; DEFAULTS['vless']=sys.argv[1]; "
                    "clients.backend=lambda *a: ([sys.executable, '-c', \"import time; time.sleep(0.8); print('vless://PRIVATE-RESULT')\"],dict(__import__('os').environ)); "
                    "run(demo(),dict(DEFAULTS,vless=sys.argv[1],database=sys.argv[2]))")
            process = subprocess.Popen([sys.executable, "-B", "-c", code, str(cfgpath), str(Path(tmp)/"missing.db")],
                stdin=slave, stdout=slave, stderr=slave, env=dict(os.environ, TERM="xterm-256color"))
            os.close(slave)
            output = bytearray()
            def until(text):
                deadline = time.monotonic()+8
                while text not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        try:
                            output.extend(os.read(master, 65536))
                        except OSError:
                            break
                self.assertIn(text, output, output.decode(errors="replace"))
            try:
                until(b"WARDEN")
                os.write(master, b"8")
                until(b"CLIENTS / Up-Down")
                os.write(master, b"a")
                until(b"ADD CLIENT")
                os.write(master, b"qa-client")
                # Curses sends incremental cursor updates, not the whole name.
                until(b"t_")
                os.write(master, b"\x1b")
                time.sleep(0.3)
                os.write(master, b"s")
                until(b"y: apply | n/Esc: cancel")
                os.write(master, b"y")
                until(b"RUNNING")
                os.write(master, b"q")  # Must not terminate a running update.
                until(b"PRIVATE-RESULT")
                os.write(master, b"\x1b")
                time.sleep(0.3)
                os.write(master, b"q")
                process.wait(timeout=8)
                self.assertEqual(process.returncode, 0)
                self.assertNotIn(b"Action and client", output)
                self.assertNotIn(b"Traceback", output)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)


@unittest.skipUnless(sys.platform == "linux", "Linux shell helper with isolated files and stub services")
class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = self.root / "vless.json"
        self.cfg.write_text(json.dumps(fixture()))
        self.envfile = self.root / "vless.env"
        self.envfile.write_text("VLESS_DOMAIN=example.org\nVLESS_WS_PATH=/test\n")
        self.log = self.root / "calls.jsonl"
        binpath = self.root / "bin"
        binpath.mkdir()
        # These stand-ins only log invocations. They cannot touch any real service,
        # firewall or subscription. All backend paths are replaced below.
        driver = '''import json, os, pathlib, sys
tool = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_LOG"], "a") as f: f.write(json.dumps([tool] + args) + "\\n")
if tool == "id": print("0")
fail = os.environ.get("TEST_FAIL")
if (tool == "sing-box" and fail == "check") or (tool == "systemctl" and args[0] == "restart" and fail == "restart") or (tool == "subscriptions" and args[0] == "sync" and fail == "subscriptions"):
    sys.exit(1)
if tool == "accounting" and fail in ("bind", "mark"):
    p = pathlib.Path(os.environ["TEST_CONFIG"])
    data = json.loads(p.read_text())
    data["outbounds"][0]["inet4_bind_address" if fail == "bind" else "routing_mark"] = "10.90.0.2" if fail == "bind" else 9999
    p.write_text(json.dumps(data))
'''
        for tool in ("id", "systemctl", "sing-box", "nginx", "subscriptions", "accounting"):
            path = binpath / tool
            path.write_text("#!" + sys.executable + "\n" + driver)
            path.chmod(0o755)
        source = clients.HELPER.read_text()
        replacements = {
            "/etc/sing-box/vless-ws.json": str(self.cfg),
            "/run/lock/ravelin-vless-ws-users.lock": str(self.root / "users.lock"),
            "/run/lock/ravelin-policy-routing.lock": str(self.root / "policy.lock"),
            "/usr/local/sbin/ravelin-vless-subscriptions": str(binpath / "subscriptions"),
            "/usr/local/sbin/ravelin-vless-traffic-accounting": str(binpath / "accounting"),
            "/root/ravelin-vless-ws-users-backup-": str(self.root / "backup-"),
        }
        for old, new in replacements.items():
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.script = self.root / "users.sh"
        self.script.write_text(source)
        self.env = dict(os.environ, PATH=str(binpath) + os.pathsep + os.environ["PATH"],
                        VLESS_ENV_FILE=str(self.envfile), TEST_LOG=str(self.log), TEST_CONFIG=str(self.cfg))

    def run_helper(self, action, name, fail=""):
        return subprocess.run(["/bin/sh", str(self.script), action, name],
                              env=dict(self.env, TEST_FAIL=fail), capture_output=True, text=True, timeout=15)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_add_rotate_remove_preserve_routing_and_call_subscriptions(self):
        original = fixture()
        for action in ("add", "rotate", "show", "remove"):
            before = json.loads(self.cfg.read_text())
            result = self.run_helper(action, "carol")
            self.assertEqual(result.returncode, 0, result.stderr)
            after = json.loads(self.cfg.read_text())
            self.assertEqual(after["outbounds"], original["outbounds"])
            self.assertEqual(after["route"], original["route"])
            self.assertEqual(after["inbounds"][0]["users"][:2], original["inbounds"][0]["users"])
            if action == "rotate":
                self.assertNotEqual(before["inbounds"][0]["users"][2]["uuid"], after["inbounds"][0]["users"][2]["uuid"])
        self.assertEqual(json.loads(self.cfg.read_text()), original)
        self.assertEqual(sum(c[:2] == ["subscriptions", "sync"] for c in self.calls()), 4)
        self.assertEqual(sum(c == ["systemctl", "restart", "sing-box-vless-ws.service"] for c in self.calls()), 3)
        self.assertEqual(len(list(self.root.glob("backup-*"))), 3)

    def test_validation_failure_never_installs_or_restarts(self):
        before = self.cfg.read_bytes()
        result = self.run_helper("rotate", "alice", "check")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.cfg.read_bytes(), before)
        self.assertFalse(any(c[:2] == ["systemctl", "restart"] for c in self.calls()))
        self.assertFalse(list(self.root.glob("backup-*")))

    def test_bad_accounting_restores_source_and_marks_before_restart(self):
        for failure in ("bind", "mark"):
            with self.subTest(failure=failure):
                result = self.run_helper("rotate", "alice", failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads(self.cfg.read_text()), fixture())
        self.assertFalse(any(c[:2] == ["systemctl", "restart"] for c in self.calls()))

    def test_failed_restart_restores_configuration(self):
        result = self.run_helper("rotate", "alice", "restart")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.cfg.read_text()), fixture())

    def test_subscription_failure_is_nonzero_after_credentials_changed(self):
        result = self.run_helper("rotate", "alice", "subscriptions")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(json.loads(self.cfg.read_text())["inbounds"][0]["users"][0]["uuid"], "PRIVATE-ALICE")

    def test_lock_contention_does_not_change_config(self):
        import fcntl
        with (self.root / "users.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_helper("rotate", "alice")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.cfg.read_text()), fixture())

    def test_missing_settings_and_last_client_refuse_before_changes(self):
        self.envfile.write_text("VLESS_DOMAIN=example.org\n")
        result = self.run_helper("rotate", "alice")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.cfg.read_text()), fixture())
        self.envfile.write_text("VLESS_DOMAIN=example.org\nVLESS_WS_PATH=/test\n")
        single = fixture()
        single["inbounds"][0]["users"] = single["inbounds"][0]["users"][:1]
        self.cfg.write_text(json.dumps(single))
        result = self.run_helper("remove", "alice")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.cfg.read_text()), single)
