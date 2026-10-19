"""Isolated service/route model: no host systemctl, network or VPN mutations."""
import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import types
import unittest
import uuid
from unittest.mock import Mock, patch

from warden import channel_admin as a, core, lifecycle_backend as b, maintenance_backend, linux
from warden.cli import main


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.registry = self.root / "channels.json"
        self.channel = dict(id="reserve", **{"if": "awgfp3"}, peer="10.90.1.1", local="10.90.1.2",
                            public="192.0.2.2", rank=30, enabled=False, maintenance=True,
                            transport={"kind": "wss"}, table=10413, mark=66579, priority=93)
        self.other = dict(self.channel, id="primary", **{"if": "awgfp2"}, enabled=True, maintenance=False,
                          rank=10, table=10412, peer="10.90.2.1", local="10.90.2.2")
        self.registry.write_text(json.dumps({"version": 2, "channels": [self.other, self.channel]}))
        for target, value in (("STOP_DIR", self.root / "stopped"), ("UNIT_DIR", self.root / "systemd")):
            p = patch.object(b, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(b, "secure")  # Windows permissions differ; production never skips this check.
        p.start()
        self.addCleanup(p.stop)
        p = patch.dict(core.DEFAULTS, registry=str(self.registry))
        p.start()
        self.addCleanup(p.stop)
        self.cfg = dict(core.DEFAULTS)
        self.config = self.root / "awgfp3.conf"
        self.profile = "[Interface]\nTable = off\nPrivateKey = not-a-real-key\n[Peer]\nPublicKey = not-a-real-key\n"
        self.config.write_text(self.profile)
        self.group = ["awg-quick@awgfp3.service", "forpost-wss-awgfp3.service"]
        self.states = {}
        for unit in self.group:
            fragment = self.root / unit
            fragment.write_text("[Service]\nExecStart=/bin/true\n")
            self.states[unit] = dict(Id=unit, LoadState="loaded", ActiveState="active", StopWhenUnneeded="no",
                                     FragmentPath=str(fragment), DropInPaths="", Conflicts="shutdown.target",
                                     PartOf="awg-quick.target" if unit == self.group[0] else "",
                                     Requires="sysinit.target " + (self.group[1] if unit == self.group[0] else ""),
                                     RequiredBy=self.group[0] if unit == self.group[1] else "")
        self.up, self.src_mark, self.active = True, "1", "primary"
        self.healthy = {"primary": True}
        self.commands, self.rollbacks, self.fail_at = [], 0, None
        self.route_data = {10400: [{"dst": "default", "type": "unreachable", "metric": 42760}],
                           10413: [{"dst": "default", "type": "unreachable", "metric": 42760}]}
        for table in self.route_data:
            self.route_data[table].append(dict(dst="10.90.1.1", dev="awgfp3", scope="link"))
        self.route_data[10413].append(dict(dst="default", gateway="10.90.1.1", dev="awgfp3", metric=100))

        def require(ok, message):
            if not ok:
                raise ValueError(message)
        self.p = types.SimpleNamespace(CHANNELS=self.registry, AWG_DIR=self.root, SOURCE="10.78.254.2",
            require=require, locked=lambda **kw: contextlib.nullcontext(), secure_file=lambda path: path,
            parse_awg=self.parse_awg, run=self.fake_run, routes=lambda table: copy.deepcopy(self.route_data[table]),
            active_route=lambda: self.active, probe_paths=lambda: (self.healthy, {}),
            interface_exists=lambda interface: self.up, address_on=lambda *args: self.up,
            out=lambda *args: self.src_mark, probe_src_valid_mark=lambda c: "net.ipv4.conf.awgfp3.src_valid_mark",
            probe_reply_present=lambda c: True, rule_matches=lambda *args: True,
            jrun=lambda *args: [{"priority": 99, "iif": "lo", "src": "10.78.254.2", "table": 10400}],
            expected_default=lambda c, t: ["ip", "-4", "route", "replace", "default", "via", c["peer"], "dev", c["if"], "onlink", "table", str(t), "metric", "100"],
            delete_default=lambda c, t: ["ip", "-4", "route", "del", "default", "table", str(t)],
            load_channels=Mock(), validate_channels=Mock())

        @contextlib.contextmanager
        def transaction(host, args):
            journal = []
            def file(path, data, mode=0o600):
                old = path.read_bytes() if path.exists() else None
                journal.append(("file", path, old))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            def delete(path):
                journal.append(("file", path, path.read_bytes()))
                path.unlink()
            def command(argv, undo):
                journal.append(("command", undo))
                self.fake_run(argv)
                if self.fail_at and self.fail_at(argv):
                    raise KeyboardInterrupt()
            try:
                yield types.SimpleNamespace(file=file, command=command, delete_file=delete)
            except BaseException:
                self.rollbacks += 1
                for entry in reversed(journal):
                    if entry[0] == "command":
                        for argv in entry[1]:
                            self.fake_run(argv)
                    elif entry[2] is None:
                        entry[1].unlink(missing_ok=True)
                    else:
                        entry[1].write_bytes(entry[2])
                self.fake_run(["systemctl", "daemon-reload"])
                raise
        self.ctl = types.SimpleNamespace(p=self.p, registry=lambda: json.loads(self.registry.read_text()),
            change=transaction, encode=lambda d: json.dumps(d).encode(), verify_vless=Mock(), say=Mock(),
            probe_candidate=Mock(side_effect=lambda c: self.assertTrue(self.up and self.src_mark == "1")),
            probe_reply_change=lambda tx, c: tx.command(["sysctl", "-q", "-w", "key=1"], [["sysctl", "-q", "-w", "key=0"]]))

    @staticmethod
    def parse_awg(text):
        section, result = None, {"Interface": {}, "Peer": {}}
        for line in text.splitlines():
            if line.startswith("["):
                section = line[1:-1]
            elif "=" in line:
                key, value = line.split("=", 1)
                result[section][key.strip()] = value.strip()
        return result

    def fake_run(self, argv):
        self.commands.append(list(argv))
        if argv[:2] == ["systemctl", "show"]:
            return types.SimpleNamespace(stdout="\n".join(k + "=" + v for k, v in self.states[argv[2]].items()))
        if argv[:2] == ["systemctl", "daemon-reload"]:
            for unit in self.group:
                drop = b.UNIT_DIR / (unit + ".d") / "90-warden-stop.conf"
                self.states[unit]["DropInPaths"] = drop.as_posix() if drop.exists() else ""
        if argv[0] == "systemctl" and argv[1] in ("stop", "start"):
            unit = argv[2]
            if argv[1] == "start":
                if (b.STOP_DIR / "awgfp3").exists():
                    return types.SimpleNamespace(stdout="", returncode=0)  # Condition skipped.
                self.states[unit]["ActiveState"] = "active"
                if unit == self.group[0]:
                    self.up, self.src_mark = True, "0"
            else:
                self.states[unit]["ActiveState"] = "inactive"
                if unit == self.group[0]:
                    self.up = False
                    for table in self.route_data:
                        self.route_data[table] = [r for r in self.route_data[table] if r.get("dev") != "awgfp3"]
        if argv[0] == "sysctl":
            self.src_mark = argv[-1].split("=")[1]
        if argv[:3] == ["ip", "-4", "route"]:
            table, dst = int(argv[argv.index("table")+1]), argv[4]
            self.assertTrue(self.up, "Rollback routes must be restored after AWG starts")
            self.route_data[table] = [r for r in self.route_data[table] if r.get("type") == "unreachable" or r.get("dst", "").removesuffix("/32") != dst.removesuffix("/32")]
            if argv[3] != "del":
                row = dict(dst=dst, dev="awgfp3")
                row.update(dict(gateway="10.90.1.1", metric=100) if dst == "default" else dict(scope="link"))
                self.route_data[table].append(row)
        return types.SimpleNamespace(stdout="", returncode=0)

    def args(self, action):
        return types.SimpleNamespace(id="reserve", action=action, expected=hashlib.sha256(self.registry.read_bytes()).hexdigest())

    def invoke(self, action):
        b.lifecycle(self.ctl, self.args(action))

    def icmp(self):
        data = json.loads(self.registry.read_text())
        data["channels"][1]["transport"]["kind"] = "icmp"
        self.registry.write_text(json.dumps(data))
        old = self.group[1]
        self.group[1] = "forpost-faketcp-awgfp3.service"
        self.states[self.group[1]] = self.states.pop(old)
        self.states[self.group[1]]["Id"] = self.group[1]
        self.states[self.group[0]]["Requires"] = self.group[1]
        self.p.TARGETS = [("192.0.2." + str(i), "example.invalid", "/") for i in range(1, 4)]

    def test_icmp_start_requires_explicit_coordination_before_mutation(self):
        self.icmp()
        self.invoke("stop")
        count = len(self.commands)
        with self.assertRaisesRegex(ValueError, "wait-for-server-reset"):
            self.invoke("start")
        self.assertEqual(count, len(self.commands))
        self.assertFalse(self.up)
        plan = a.lifecycle_plan(self.cfg, "reserve", "start")
        with self.assertRaisesRegex(ValueError, "wait-for-server-reset"):
            a.backend(self.cfg, plan)
        self.assertIn("--wait-for-server-reset", " ".join(a.format_plan(plan)))

    def test_icmp_waits_for_reset_then_requires_three_successes(self):
        self.icmp()
        self.invoke("stop")
        now, calls = [0.0], []
        def probe(c, target, deadline=None, observation=None):
            self.assertLess(now[0], deadline)
            self.assertLessEqual(deadline-now[0], 5)
            now[0] += 1
            calls.append(target)
            observation.update(target=target[0], stage="tcp", reason="timeout", private="DO-NOT-LOG")
            # Simulate a reset after one failed round; a partial round is insufficient.
            return len(calls) > 3 and len(calls) != 5
        self.p.probe_one = probe
        args = self.args("start")
        args.wait_for_server_reset = True
        with patch.object(b.time, "monotonic", side_effect=lambda: now[0]), patch.object(b.time, "sleep", side_effect=lambda n: now.__setitem__(0, now[0]+n)):
            b.lifecycle(self.ctl, args)
        self.assertEqual(len(calls), 9)
        self.assertTrue(self.up)
        row = core.channels(self.cfg)[1][1]
        self.assertTrue(row["maintenance"])
        self.assertFalse(row["enabled"])
        self.assertFalse(row["stopped"])
        self.assertEqual(self.active, "primary")
        text = " ".join(str(c) for c in self.ctl.say.call_args_list)
        self.assertIn("Client AWG/transport ready", text)
        self.assertNotIn("DO-NOT-LOG", text)
        self.ctl.probe_candidate.assert_not_called()

    def test_icmp_wait_timeout_rolls_back_to_stopped(self):
        self.icmp()
        self.invoke("stop")
        original = self.registry.read_bytes()
        now = [0.0]
        def probe(c, target, deadline=None, observation=None):
            now[0] = deadline  # Every probe exhausts its own bounded budget.
            observation.update(target=target[0], stage="tls", reason="timeout")
            return False
        self.p.probe_one = probe
        args = self.args("start")
        args.wait_for_server_reset = True
        with patch.object(b.time, "monotonic", side_effect=lambda: now[0]), patch.object(b.time, "sleep", side_effect=lambda n: now.__setitem__(0, now[0]+n)), self.assertRaisesRegex(ValueError, "server-reset wait"):
            b.lifecycle(self.ctl, args)
        self.assertEqual(now[0], 90)
        self.assertFalse(self.up)
        self.assertEqual(self.registry.read_bytes(), original)
        self.assertTrue((b.STOP_DIR / "awgfp3").exists())
        self.assertTrue(all(s["ActiveState"] == "inactive" for s in self.states.values()))

    def test_icmp_wait_api_rejected_before_transaction(self):
        self.icmp()
        self.invoke("stop")
        self.p.probe_one = lambda c, target: True
        args = self.args("start")
        args.wait_for_server_reset = True
        with self.assertRaisesRegex(ValueError, "bounded startup"):
            b.lifecycle(self.ctl, args)
        self.assertFalse(self.up)
        self.assertEqual(self.rollbacks, 0)

    def test_interrupted_icmp_wait_restores_stopped_state(self):
        self.icmp()
        self.invoke("stop")
        def probe(c, target, deadline=None, observation=None):
            raise KeyboardInterrupt()
        self.p.probe_one = probe
        args = self.args("start")
        args.wait_for_server_reset = True
        with self.assertRaises(KeyboardInterrupt):
            b.lifecycle(self.ctl, args)
        self.assertFalse(self.up)
        self.assertTrue((b.STOP_DIR / "awgfp3").exists())
        self.assertTrue(core.channels(self.cfg)[1][1]["stopped"])

    def test_icmp_tui_preview_explains_coordination_and_shows_live_wait(self):
        self.icmp()
        self.invoke("stop")
        with patch.object(a, "backend"), patch.object(a, "start") as start:
            view = a.PriorityView(self.cfg, "reserve", lifecycle="start")
            self.assertEqual(view.mode, "confirm")
            self.assertTrue(view.pending["wait_for_server_reset"])
            self.assertIn("separate console", " ".join(view.render(100)))
            view.handle("y")
            start.assert_called_once()
            start.return_value.done.return_value = False
            start.return_value.progress.return_value = ["[WAIT] Client AWG/transport ready"]
            self.assertTrue(view.poll())
            self.assertIn("Client AWG/transport ready", " ".join(view.render(100)))
            self.assertTrue(view.handle("q"))

    def test_reset_option_rejected_for_other_operations(self):
        with self.assertRaisesRegex(ValueError, "only for ICMP Start"):
            a.lifecycle_plan(self.cfg, "reserve", "stop", True)
        self.invoke("stop")
        with self.assertRaisesRegex(ValueError, "only for ICMP Start"):
            a.lifecycle_plan(self.cfg, "reserve", "start", True)

    def test_stop_survives_controller_wants_and_start_keeps_maintenance(self):
        original = self.config.read_bytes()
        self.invoke("stop")
        stopped = core.channels(self.cfg)[1][1]
        self.assertTrue(stopped["stopped"])
        self.assertFalse(self.up)
        self.fake_run(["systemctl", "start", self.group[0]])  # Controller/boot Wants.
        self.assertFalse(self.up)
        with self.assertRaisesRegex(ValueError, "Start"):
            a.maintenance_plan(self.cfg, "reserve", "off")
        self.invoke("start")
        row = core.channels(self.cfg)[1][1]
        self.assertTrue(self.up)
        self.assertFalse(row["stopped"])
        self.assertTrue(row["maintenance"])
        self.assertFalse(row["enabled"])
        self.assertEqual(self.active, "primary")
        self.assertEqual(original, self.config.read_bytes())
        self.assertEqual(json.loads(self.registry.read_text())["channels"][0], self.other)
        self.ctl.probe_candidate.assert_called_once()
        self.assertFalse(any("disable" in c or "enable" in c for c in self.commands))
        self.invoke("stop")  # The installed drop-in is reusable.

    def test_icmp_transport_uses_only_selected_pair(self):
        data = json.loads(self.registry.read_text())
        data["channels"][1]["transport"]["kind"] = "icmp"
        self.registry.write_text(json.dumps(data))
        old = self.group[1]
        self.group[1] = "forpost-faketcp-awgfp3.service"
        self.states[self.group[1]] = self.states.pop(old)
        self.states[self.group[1]]["Id"] = self.group[1]
        self.states[self.group[0]]["Requires"] = self.group[1]
        self.invoke("stop")
        self.assertIn(["systemctl", "stop", self.group[1]], self.commands)
        self.assertNotIn(["systemctl", "stop", old], self.commands)

    def test_failed_start_probe_restores_stopped_state_and_routes(self):
        self.invoke("stop")
        saved = self.registry.read_bytes()
        self.ctl.probe_candidate.side_effect = ValueError("HTTPS failed")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            self.invoke("start")
        self.assertFalse(self.up)
        self.assertEqual(self.registry.read_bytes(), saved)
        self.assertTrue((b.STOP_DIR / "awgfp3").exists())
        self.assertTrue(all(s["ActiveState"] == "inactive" for s in self.states.values()))

    def test_stop_failure_after_persistent_files_rolls_back_link_mark_and_routes(self):
        original, routes = self.registry.read_bytes(), copy.deepcopy(self.route_data)
        self.ctl.verify_vless.side_effect = ValueError("VLESS changed")
        with self.assertRaisesRegex(ValueError, "VLESS"):
            self.invoke("stop")
        self.assertTrue(self.up)
        self.assertEqual(self.src_mark, "1")
        self.assertEqual(self.registry.read_bytes(), original)
        self.assertFalse((b.STOP_DIR / "awgfp3").exists())
        self.assertEqual(len(self.route_data[10400]), len(routes[10400]))
        self.assertEqual(len(self.route_data[10413]), len(routes[10413]))

    def test_interruption_after_transport_stop_recovers_in_dependency_order(self):
        self.fail_at = lambda argv: argv == ["systemctl", "stop", self.group[1]]
        with self.assertRaises(KeyboardInterrupt):
            self.invoke("stop")
        starts = [c for c in self.commands if c[:2] == ["systemctl", "start"]]
        self.assertEqual(starts, [["systemctl", "start", u] for u in reversed(self.group)])
        self.assertTrue(self.up)
        self.assertEqual(self.rollbacks, 1)

    def test_only_healthy_egress_and_maintenance_required(self):
        self.healthy["primary"] = False
        with self.assertRaisesRegex(ValueError, "unhealthy"):
            self.invoke("stop")
        self.assertTrue(self.up)
        self.healthy["primary"] = True
        self.active = "reserve"
        with self.assertRaisesRegex(ValueError, "different active"):
            self.invoke("stop")
        with self.assertRaises(ValueError):
            a.lifecycle_plan(self.cfg, "primary", "stop")

    def test_configuration_and_unit_drift_refuse_start(self):
        self.invoke("stop")
        self.config.write_text(self.profile + "# drift\n")
        with self.assertRaisesRegex(ValueError, "changed since Stop"):
            self.invoke("start")
        self.config.write_text(self.profile)
        Path(self.states[self.group[1]]["FragmentPath"]).write_text("# drift")
        with self.assertRaisesRegex(ValueError, "changed since Stop"):
            self.invoke("start")
        self.assertFalse(self.up)

    def test_foreign_dependencies_hooks_saveconfig_and_unsafe_routes_refused(self):
        for key in ("Requires", "Wants", "RequiredBy", "BoundBy", "ConsistsOf", "PartOf", "BindsTo", "PropagatesStopTo", "Conflicts"):
            with self.subTest(key=key):
                old = self.states[self.group[0]].get(key, "")
                self.states[self.group[0]][key] = "unrelated.service"
                with self.assertRaisesRegex(ValueError, "Foreign service"):
                    self.invoke("stop")
                self.states[self.group[0]][key] = old
        for field in ("PostDown = do-not-run", "SaveConfig = true", "DNS = 1.1.1.1"):
            self.config.write_text(self.profile.replace("Table = off", "Table = off\n" + field))
            with self.assertRaisesRegex(ValueError, "AWG hooks"):
                self.invoke("stop")
        self.config.write_text(self.profile)
        self.route_data[10413][-1]["mtu"] = 1200
        with self.assertRaisesRegex(ValueError, "Custom channel route"):
            self.invoke("stop")
        self.assertTrue(self.up)

    def test_missing_loaded_condition_or_foreign_dropin_refuses(self):
        drop = b.UNIT_DIR / (self.group[0] + ".d") / "90-warden-stop.conf"
        drop.parent.mkdir(parents=True)
        drop.write_text("# foreign")
        with self.assertRaisesRegex(ValueError, "drop-in differs"):
            self.invoke("stop")
        drop.unlink()
        self.invoke("stop")
        self.states[self.group[0]]["DropInPaths"] = ""
        with self.assertRaisesRegex(ValueError, "not loaded"):
            self.invoke("start")

    def test_preview_demo_tui_and_backend_dispatch(self):
        with patch("warden.cli.config", return_value=self.cfg), patch.object(a, "start") as start, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["stop", "reserve"]), 0)
            self.assertIn("PREVIEW ONLY", output.getvalue())
            start.assert_not_called()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--demo", "stop", "reserve", "--run"]), 2)
        with patch.object(a, "backend"), patch.object(a, "start") as start:
            view = a.PriorityView(self.cfg, "reserve", lifecycle="stop")
            self.assertEqual(view.mode, "confirm")
            self.assertIn("Stop", " ".join(view.render(80)))
            start.assert_not_called()
            view.handle("y")
            self.assertEqual(start.call_args[0][1]["action"], "stop")
        planned = a.lifecycle_plan(self.cfg, "reserve", "stop")
        with patch.object(a.sys, "platform", "linux"), patch.object(a.os, "geteuid", return_value=0, create=True), patch.object(a.os, "access", return_value=True), patch.object(a.Path, "is_file", return_value=True), patch.object(a, "ssh_connection", return_value="192.0.2.1 123 192.0.2.2 22"):
            argv, env = a.backend(self.cfg, planned)
            self.assertTrue(argv[2].endswith("lifecycle_backend.py"))
            self.assertIn("stop", argv)
            self.assertIn("SSH_CONNECTION", env)
        self.invoke("stop")
        with self.assertRaises(ValueError):
            a.backend(self.cfg, planned)

    def test_missing_probe_guard_and_foreign_start_routes_rollback(self):
        self.invoke("stop")
        self.route_data[10413].append(dict(dst="default", dev="foreign", metric=100))
        with self.assertRaisesRegex(ValueError, "Foreign probe route"):
            self.invoke("start")
        self.assertFalse(self.up)
        self.assertTrue((b.STOP_DIR / "awgfp3").exists())

    def test_maintenance_backend_cannot_resume_stopped_channel(self):
        self.invoke("stop")
        args = self.args("start")
        args.state = "off"
        with self.assertRaisesRegex(ValueError, "Start"):
            maintenance_backend.maintain(self.ctl, args)

    def test_passive_collector_displays_absent_stopped_interface(self):
        self.invoke("stop")
        with patch.object(linux, "read_json", side_effect=OSError()):
            data = linux.collect(self.cfg, runner=lambda argv: "[]" if "-j" in argv else "")
        row = next(r for r in data["tunnels"] if r["id"] == "reserve")
        self.assertEqual((row["role"], row["health"]), ("Stopped", "Down"))

    @unittest.skipUnless(sys.platform == "linux" and shutil.which("systemd-analyze"), "Linux systemd condition evaluator")
    def test_real_systemd_condition_blocks_marker_and_accepts_removed_marker(self):
        # Evaluate the actual systemd condition without loading/changing any unit.
        marker = self.root / "marker"
        command = ["systemd-analyze", "condition", "ConditionPathExists=!" + str(marker)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        marker.touch()
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
        marker.unlink()
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)


@unittest.skipUnless(sys.platform == "linux" and getattr(os, "geteuid", lambda: -1)() == 0 and shutil.which("ip"),
                     "Root Linux network namespace")
class KernelRoutesTests(unittest.TestCase):
    def test_link_removal_and_narrow_route_restore_in_real_kernel(self):
        ns = "warden-lifecycle-" + uuid.uuid4().hex[:8]
        def run(*argv):
            return subprocess.run(["ip", "netns", "exec", ns, *argv], check=True, text=True, capture_output=True)
        subprocess.run(["ip", "netns", "add", ns], check=True, capture_output=True)
        try:
            c = dict(peer="10.90.1.1", **{"if": "awgfp3"}, table=10413)
            def require(ok, message):
                if not ok:
                    raise ValueError(message)
            p = types.SimpleNamespace(require=require,
                routes=lambda t: json.loads(run("ip", "-j", "-4", "route", "show", "table", str(t)).stdout),
                expected_default=lambda c, t: ["ip", "-4", "route", "replace", "default", "via", c["peer"], "dev", c["if"], "onlink", "table", str(t), "metric", "100"])
            def link():
                run("ip", "link", "add", "awgfp3", "type", "dummy")
                run("ip", "addr", "add", "10.90.1.2/32", "dev", "awgfp3")
                run("ip", "link", "set", "awgfp3", "up")
            link()
            for table in (10400, 10413):
                run("ip", "route", "add", "unreachable", "default", "table", str(table), "metric", "42760")
                run("ip", "route", "add", "10.90.1.1/32", "dev", "awgfp3", "scope", "link", "table", str(table))
            run(*p.expected_default(c, 10413))
            restore = b.route_commands(p, c)  # Validate actual iproute2 JSON, not a fixture.
            run("ip", "link", "del", "awgfp3")
            for table in (10400, 10413):
                self.assertTrue(all(r.get("type") == "unreachable" for r in p.routes(table)))
            link()
            for command in restore:
                run(*command)
            self.assertEqual(b.route_commands(p, c), restore)
        finally:
            subprocess.run(["ip", "netns", "del", ns], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
