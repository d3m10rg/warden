import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from warden import channel_admin as a, maintenance_backend as b, core, linux
from warden.cli import main


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)/"channels.json"
        self.rows = [dict(id="primary", **{"if": "awgfp2"}, peer="10.90.0.1", local="10.90.0.2",
                          public="192.0.2.1", rank=10, enabled=True, transport={"kind": "icmp"}),
                     dict(id="reserve", **{"if": "awgfp3"}, peer="10.90.1.1", local="10.90.1.2",
                          public="192.0.2.2", rank=30, enabled=True, transport={"kind": "wss"})]
        self.path.write_text(json.dumps({"version": 2, "channels": self.rows}))
        patcher = patch.dict(core.DEFAULTS, registry=str(self.path))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cfg = dict(core.DEFAULTS)
        self.active, self.healthy = "primary", {"primary": True, "reserve": True}
        self.rolled_back = False
        def require(ok, message):
            if not ok:
                raise ValueError(message)
        self.p = types.SimpleNamespace(CHANNELS=self.path, SOURCE="10.78.254.2", require=require,
            locked=lambda **kwargs: contextlib.nullcontext(),
            routes=lambda table: [{"dst": "default", "type": "unreachable"}],
            jrun=lambda *args: [{"priority": 99, "iif": "lo", "src": "10.78.254.2", "table": 10400}],
            active_route=lambda: self.active, probe_paths=lambda: (self.healthy, {}),
            load_channels=Mock(), validate_channels=Mock())
        def switch(tx, target):
            self.active = target
        @contextlib.contextmanager
        def transaction(host, args):
            # Isolated actual files, fake shared transaction implements its
            # documented rollback contract. Never invokes real system services.
            previous, active = self.path.read_bytes(), self.active
            try:
                yield types.SimpleNamespace(file=lambda path, data: path.write_bytes(data))
            except BaseException:
                self.path.write_bytes(previous)
                self.active, self.rolled_back = active, True
                raise
        self.ctl = types.SimpleNamespace(p=self.p, registry=lambda: json.loads(self.path.read_text()),
            change=transaction, switch=Mock(side_effect=switch), encode=lambda d: json.dumps(d).encode(),
            probe_candidate=Mock(), verify_vless=Mock(), say=Mock())

    def args(self, entity="primary", state="on"):
        return types.SimpleNamespace(id=entity, state=state,
            expected=hashlib.sha256(self.path.read_bytes()).hexdigest())

    def test_active_channel_handover_preserves_transport_and_rank(self):
        self.healthy["primary"] = False  # Incident: ICMP failed, WSS is the working exit.
        b.maintain(self.ctl, self.args())
        self.assertEqual(self.active, "reserve")
        self.ctl.switch.assert_called_once()
        rows = json.loads(self.path.read_text())["channels"]
        self.assertFalse(rows[0]["enabled"])
        self.assertTrue(rows[0]["maintenance"])
        self.assertEqual(rows[0]["rank"], 10)
        self.assertEqual(rows[1], self.rows[1])
        self.assertEqual(rows[1]["transport"]["kind"], "wss")
        self.ctl.verify_vless.assert_called_once()

    def test_standby_exclusion_does_not_switch_exit(self):
        b.maintain(self.ctl, self.args("reserve"))
        self.assertEqual(self.active, "primary")
        self.ctl.switch.assert_not_called()

    def test_only_working_wss_cannot_be_excluded(self):
        self.active, self.healthy = "reserve", {"primary": False, "reserve": True}
        previous = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "healthy alternative"):
            b.maintain(self.ctl, self.args("reserve"))
        self.assertTrue(self.rolled_back)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.active, "reserve")

    def test_failure_after_route_and_registry_write_rolls_back(self):
        previous = self.path.read_bytes()
        self.ctl.verify_vless.side_effect = ValueError("test verification failure")
        with self.assertRaisesRegex(ValueError, "verification"):
            b.maintain(self.ctl, self.args())
        self.assertTrue(self.rolled_back)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.active, "primary")

    def test_return_probes_before_enabling_and_preserves_selected_exit(self):
        b.maintain(self.ctl, self.args())
        self.ctl.switch.reset_mock()
        b.maintain(self.ctl, self.args(state="off"))
        self.ctl.probe_candidate.assert_called_once()
        rows = json.loads(self.path.read_text())["channels"]
        self.assertTrue(rows[0]["enabled"])
        self.assertFalse(rows[0]["maintenance"])
        self.assertEqual(self.active, "reserve")
        self.ctl.switch.assert_not_called()

    def test_failed_return_probe_keeps_maintenance(self):
        b.maintain(self.ctl, self.args())
        previous = self.path.read_bytes()
        self.ctl.probe_candidate.side_effect = ValueError("HTTPS failed")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            b.maintain(self.ctl, self.args(state="off"))
        self.assertEqual(self.path.read_bytes(), previous)

    def test_stale_registry_refused_under_lock(self):
        args = self.args()
        self.path.write_text(self.path.read_text()+"\n")
        with self.assertRaisesRegex(ValueError, "Registry changed"):
            b.maintain(self.ctl, args)
        self.ctl.switch.assert_not_called()

    def test_missing_guards_and_last_enabled_channel_refused(self):
        self.rows[1]["enabled"] = False
        self.path.write_text(json.dumps({"version": 2, "channels": self.rows}))
        with self.assertRaisesRegex(ValueError, "last enabled"):
            b.maintain(self.ctl, self.args())
        self.rows[1]["enabled"] = True
        self.path.write_text(json.dumps({"version": 2, "channels": self.rows}))
        self.p.routes = lambda *args: []
        with self.assertRaisesRegex(ValueError, "unreachable"):
            b.maintain(self.ctl, self.args())

    def test_passive_frontend_and_persistent_display(self):
        with patch("warden.cli.config", return_value=self.cfg), patch.object(a, "start") as start, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["maintenance", "reserve", "on"]), 0)
            self.assertIn("PREVIEW ONLY", output.getvalue())
            start.assert_not_called()
        b.maintain(self.ctl, self.args())
        rows = core.channels(self.cfg)[1]
        self.assertTrue(rows[0]["maintenance"])
        self.assertEqual(rows[1]["transport"], "wss")
        plan = a.maintenance_plan(self.cfg, "primary", "off")
        self.assertEqual(plan["state"], "off")
        with self.assertRaises(ValueError):
            a.maintenance_plan(self.cfg, "reserve", "off")

    def test_unknown_and_permanent_channels_refused(self):
        for entity in ("awg0", "missing"):
            with self.assertRaises(ValueError):
                a.maintenance_plan(self.cfg, entity, "on")

    def test_tui_requires_confirmation_and_rechecks_before_start(self):
        with patch.object(a, "backend"), patch.object(a, "start") as start:
            view = a.PriorityView(self.cfg, "reserve", maintenance="on")
            self.assertEqual(view.mode, "confirm")
            self.assertIn("Maintenance: on", " ".join(view.render(100)))
            start.assert_not_called()
            view.handle("n")
            self.assertEqual(view.mode, "closed")
            view = a.PriorityView(self.cfg, "reserve", maintenance="on")
            view.handle("y")
            start.assert_called_once()
            self.assertEqual(start.call_args[0][1]["state"], "on")
            self.assertTrue(view.handle("q"))
            self.assertEqual(view.mode, "running")

    def test_wss_service_observed_and_disabled_does_not_hide_interface(self):
        calls = []
        def runner(argv):
            calls.append(argv)
            if "link" in argv:
                return '[{"ifname":"awgfp2"},{"ifname":"awgfp3"}]'
            return "[]" if "-j" in argv else ""
        b.maintain(self.ctl, self.args())
        with patch.object(linux, "read_json", side_effect=OSError()):
            # channels reads through core.read_json independently.
            data = linux.collect(self.cfg, runner=runner)
        self.assertEqual(data["tunnels"][0]["role"], "Maintenance")
        self.assertTrue(any("forpost-wss-awgfp3.service" in c for c in calls))
        self.assertFalse(any("forpost-faketcp-awgfp3.service" in c for c in calls))
