import base64
import json
from pathlib import Path
import runpy
import tempfile
import unittest


recovery = runpy.run_path(str(Path(__file__).resolve().parent.parent / "helpers/recover-clients-env.py"))


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.token = "a" * 64
        self.uri = "vless://PRIVATE-UUID@example.org:443?path=%2Ftest"
        self.policy = self.root / "policy.json"
        self.config = self.root / "vless.json"
        self.config.write_text(json.dumps({"inbounds": [{"tag": "vless-ws", "type": "vless", "transport": {"type": "ws", "path": "/test"}}]}))
        self.include = self.root / "nginx.conf"
        self.include.write_text("location = /sub/" + self.token + " {\n}")
        (self.root / self.token).write_text(self.uri)
        profile = {"Name": "ru-direct", "LastUpdated": 1, "GlobalProxy": True}
        (self.root / (self.token + ".happ")).write_text("happ://routing/add/" + base64.b64encode(json.dumps(profile).encode()).decode() + "\n" + self.uri + "\n")
        self.renderer = {"read_users": lambda: [{"name": "test", "uuid": "PRIVATE-UUID"}],
                         "load_store": lambda: {"test": {"token": self.token}},
                         "SUBSCRIPTION_DIR": self.root, "NGINX_INCLUDE": self.include, "CONFIG_PATH": self.config,
                         "make_vless_uri": lambda env, user: self.uri,
                         "render_happ_profiles": lambda env: (self.policy, [dict(profile, LastUpdated=99)])}

    def test_reconstructs_settings_without_credentials_or_writes(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        content = recovery["build"](self.renderer, self.policy)
        self.assertIn("VLESS_DOMAIN='example.org'", content)
        self.assertIn("VLESS_WS_PATH='/test'", content)
        self.assertNotIn("PRIVATE-UUID", content)
        self.assertNotIn(self.token, content)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_mismatched_happ_policy_is_refused(self):
        self.renderer["render_happ_profiles"] = lambda env: (self.policy, [{"Name": "ru-direct", "GlobalProxy": False}])
        with self.assertRaisesRegex(ValueError, "does not reproduce"):
            recovery["build"](self.renderer, self.policy)

    def test_stale_credentials_or_ws_path_are_refused(self):
        for uri in (self.uri.replace("PRIVATE-UUID", "OLD-UUID"), self.uri.replace("%2Ftest", "%2Fold")):
            (self.root / self.token).write_text(uri)
            with self.assertRaises(ValueError):
                recovery["build"](self.renderer, self.policy)

    def test_missing_prefix_is_refused(self):
        self.include.write_text("")
        with self.assertRaisesRegex(ValueError, "prefix"):
            recovery["build"](self.renderer, self.policy)

    def test_only_explicit_missing_client_can_be_excluded(self):
        self.renderer["read_users"] = lambda: [
            {"name": "test", "uuid": "PRIVATE-UUID"}, {"name": "new-client", "uuid": "NEW-PRIVATE"}]
        with self.assertRaisesRegex(ValueError, "exactly"):
            recovery["build"](self.renderer, self.policy)
        with self.assertRaisesRegex(ValueError, "exactly"):
            recovery["build"](self.renderer, self.policy, ["other-client"])
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        content = recovery["build"](self.renderer, self.policy, ["new-client"])
        self.assertIn("VLESS_WS_PATH='/test'", content)
        self.assertNotIn("NEW-PRIVATE", content)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_allow_missing_does_not_bypass_existing_payload_validation(self):
        self.renderer["read_users"] = lambda: [
            {"name": "test", "uuid": "PRIVATE-UUID"}, {"name": "new-client", "uuid": "NEW-PRIVATE"}]
        (self.root / self.token).write_text(self.uri.replace("PRIVATE-UUID", "OLD-UUID"))
        with self.assertRaisesRegex(ValueError, "credentials"):
            recovery["build"](self.renderer, self.policy, ["new-client"])

    def test_orphans_and_empty_store_are_always_refused(self):
        for records in ({}, {"orphan": {"token": self.token}}):
            self.renderer["load_store"] = lambda: records
            with self.assertRaises(ValueError):
                recovery["build"](self.renderer, self.policy, ["test"])

    def test_stale_allow_missing_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exactly"):
            recovery["build"](self.renderer, self.policy, ["test"])

    def test_write_never_overwrites_existing_file(self):
        path = self.root / "restored.env"
        recovery["write_new"](path, "NEW")
        with self.assertRaises(FileExistsError):
            recovery["write_new"](path, "BAD")
        self.assertEqual(path.read_text(), "NEW")
        self.assertFalse(list(self.root.glob(".warden-env-*")))
