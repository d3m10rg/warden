import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

from warden import ssh_session as s


class SessionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.proc = Path(tmp.name)
        patcher = patch.dict(os.environ, SSH_CONNECTION="")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.record(100, "python3", 90)
        self.record(90, "bash", 80)
        self.record(80, "sudo", 70)
        self.record(70, "sshd-session", 1)
        fd = self.proc/"70/fd"
        fd.mkdir()
        (fd/"4").touch()
        self.net = self.proc/"70/net"
        self.net.mkdir()
        self.line = "0: 0A0200C0:107A 630200C0:C350 01 0:0 0:0 0 0 0 123\n"
        (self.net/"tcp").write_text("header\n"+self.line)

    def record(self, pid, name, parent):
        directory = self.proc/str(pid)
        directory.mkdir(exist_ok=True)
        fields = ["S", str(parent)] + ["0"]*17 + ["999"]
        (directory/"stat").write_text(f"{pid} ({name}) " + " ".join(fields))

    def test_sudo_without_environment_finds_own_sshd_socket(self):
        with patch.object(s.os, "readlink", return_value="socket:[123]"):
            self.assertEqual(s.resolve(self.proc, 100), "192.0.2.99 50000 192.0.2.10 4218")

    def test_valid_explicit_environment_is_preserved(self):
        with patch.dict(os.environ, SSH_CONNECTION="192.0.2.99 50000 192.0.2.10 22"):
            self.assertEqual(s.resolve(self.proc, 100), os.environ["SSH_CONNECTION"])

    def test_invalid_identity_is_not_silently_replaced(self):
        for value in ("junk", "192.0.2.99 0 192.0.2.10 22", "::1 1234 ::1 22"):
            with patch.dict(os.environ, SSH_CONNECTION=value), self.assertRaises(ValueError):
                s.resolve(self.proc, 100)

    def test_other_logins_and_closed_sockets_are_not_selected(self):
        with patch.object(s.os, "readlink", return_value="socket:[999]"), self.assertRaises(ValueError):
            s.resolve(self.proc, 100)
        (self.net/"tcp").write_text("header\n"+self.line.replace(" 01 ", " 08 "))
        with patch.object(s.os, "readlink", return_value="socket:[123]"), self.assertRaises(ValueError):
            s.resolve(self.proc, 100)

    def test_ambiguous_sockets_refused(self):
        (self.proc/"70/fd/5").touch()
        (self.net/"tcp").write_text("header\n"+self.line+self.line.replace("C350", "C351").replace("123\n", "124\n"))
        with patch.object(s.os, "readlink", side_effect=lambda p: "socket:[123]" if p.name == "4" else "socket:[124]"), self.assertRaisesRegex(ValueError, "ambiguous"):
            s.resolve(self.proc, 100)

    def test_local_console_and_detached_tree_refused(self):
        self.record(80, "sudo", 1)
        with self.assertRaisesRegex(ValueError, "automatically"):
            s.resolve(self.proc, 100)

    def test_ipv4_mapped_socket_format(self):
        self.assertEqual(s.endpoint("0000000000000000FFFF0000630200C0:C350"), ("192.0.2.99", "50000"))

    @unittest.skipUnless(sys.platform == "linux", "Real Linux process/socket observation")
    def test_real_proc_with_established_socket(self):
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            client.connect(listener.getsockname())
            accepted, remote = listener.accept()
            with accepted:
                # Own two ends gives ambiguity: close client's inherited fd
                # from the resolver view, keep only the accepted server socket.
                real_readlink = os.readlink
                accepted_link = real_readlink(f"/proc/self/fd/{accepted.fileno()}")
                real_process = s.process
                def process(proc, pid):
                    name, parent, started = real_process(proc, pid)
                    return "sshd-session", parent, started
                with patch.object(s, "process", side_effect=process), patch.object(s.os, "readlink", side_effect=lambda p: accepted_link if p.name == str(accepted.fileno()) else "other"):
                    self.assertEqual(s.resolve(), f"127.0.0.1 {remote[1]} 127.0.0.1 {listener.getsockname()[1]}")
