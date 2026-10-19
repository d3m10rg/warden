"""Resolve SSH route identity without depending on sudo environment policy."""
import ipaddress
import os
from pathlib import Path
import re
import socket


def validate(value):
    fields = value.split()
    if len(fields) != 4:
        raise ValueError("Invalid SSH connection identity")
    try:
        for index in (0, 2):
            ipaddress.IPv4Address(fields[index])
        for index in (1, 3):
            if not fields[index].isascii() or not fields[index].isdigit() or not 1 <= int(fields[index]) <= 65535:
                raise ValueError()
    except ValueError:
        raise ValueError("SSH route protection currently requires a valid IPv4 SSH connection") from None
    return " ".join(fields)


def process(proc, pid):
    text = (proc / str(pid) / "stat").read_text(encoding="ascii")
    end = text.rfind(")")
    fields = text[end+2:].split()
    return text[text.index("(")+1:end], int(fields[1]), fields[19]


def endpoint(value):
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 16:
        raw = b"".join(raw[i:i+4][::-1] for i in range(0, 16, 4))
        mapped = ipaddress.IPv6Address(raw).ipv4_mapped
        if mapped is None:
            raise ValueError("SSH route protection currently supports IPv4 connections only")
        address = str(mapped)
    else:
        address = socket.inet_ntoa(raw[::-1])
    return address, str(int(port, 16))


def resolve(proc=Path("/proc"), pid=None):
    provided = os.environ.get("SSH_CONNECTION", "")
    if provided.strip():
        return validate(provided)
    # Only sockets held by sshd processes in our own parent chain qualify.
    # Never select an arbitrary system-wide login or use last-login history.
    pid = os.getpid() if pid is None else pid
    ancestors, seen = [], set()
    try:
        for _ in range(64):
            if pid <= 1 or pid in seen:
                break
            seen.add(pid)
            name, parent, started = process(proc, pid)
            if name in ("sshd", "sshd-session"):
                inodes = set()
                for count, fd in enumerate((proc / str(pid) / "fd").iterdir()):
                    if count >= 1024:
                        raise ValueError("SSH process has too many descriptors to identify safely")
                    try:
                        match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(fd))
                        if match:
                            inodes.add(match.group(1))
                    except FileNotFoundError:
                        continue
                if process(proc, pid) != (name, parent, started):
                    raise ValueError("SSH process changed during inspection; retry")
                # Inspect the socket table in that process's network namespace.
                candidates = set()
                for kind in ("tcp", "tcp6"):
                    table = proc / str(pid) / ("net/" + kind)
                    try:
                        with table.open(encoding="ascii") as stream:
                            text = stream.read(4_000_001)
                    except FileNotFoundError:
                        continue
                    if len(text) > 4_000_000:
                        raise ValueError("SSH socket table too large to inspect safely")
                    for line in text.splitlines()[1:]:
                        fields = line.split()
                        if len(fields) > 9 and fields[3] == "01" and fields[9] in inodes:
                            local, remote = endpoint(fields[1]), endpoint(fields[2])
                            candidates.add(validate(" ".join((*remote, *local))))
                if len(candidates) > 1:
                    raise ValueError("Several SSH ancestor sockets found; connection is ambiguous")
                if candidates:
                    ancestors.append((pid, name, parent, started, candidates.pop()))
                    break  # Nearest session, not the shared listening daemon.
            pid = parent
        if ancestors:
            pid, name, parent, started, connection = ancestors[0]
            if process(proc, pid) == (name, parent, started):
                return connection
    except (OSError, IndexError, UnicodeError):
        pass
    raise ValueError("Cannot identify the originating IPv4 SSH connection automatically; "
                     "use a direct SSH session. Local/provider console and detached multiplexer sessions are not auto-authorized")
