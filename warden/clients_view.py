"""Clients page state, rendered by the same curses frame as other tabs."""
from pathlib import Path

from . import clients


class ClientsView:
    def __init__(self, cfg, demo=False):
        self.cfg, self.demo = cfg, demo
        self.users, self.selected = [], 0
        self.mode, self.text, self.rows = "list", "", []
        self.pending, self.operation = None, None
        self.offset = 0
        self.problem = ""

    def reset(self):
        self.mode, self.text, self.rows = "list", "", []
        self.pending, self.offset = None, 0

    def refresh(self):
        if self.demo:
            self.users = ["demo-client-1", "demo-client-2"]
            return
        selected = self.users[self.selected] if self.users else None
        try:
            self.users = clients.names(self.cfg)
            self.problem = ("Missing VLESS env: " + self.cfg["clients_env"] +
                            ". Configure clients_env with the runtime file; .example is not a runtime config."
                            if not Path(self.cfg["clients_env"]).is_file() else "")
        except (OSError, ValueError):
            self.users, self.problem = [], "Client list unavailable; check VLESS config and permissions."
        self.selected = self.users.index(selected) if selected in self.users else min(self.selected, max(0, len(self.users)-1))

    def preview(self, action, name):
        self.pending = None
        self.offset = 0
        try:
            self.rows = clients.preview(self.cfg, action, name)
            clients.backend(self.cfg, action, name)  # Preflight, no subprocess.
            self.pending, self.mode = (action, name), "confirm"
        except (OSError, ValueError) as exc:
            self.error(exc)

    def error(self, exc):
        self.mode, self.pending, self.offset = "result", None, 0
        self.rows = [str(exc) if type(exc) is ValueError else "Unable to read client data; check paths and permissions."]

    def poll(self):
        if self.operation and self.operation.done():
            self.rows = self.operation.result()
            self.mode = "result"
            self.operation = None
            self.refresh()
            return True
        return False

    def handle(self, key):
        """Return True when consumed; other keys belong to the shared frame."""
        if self.operation:
            return True  # Wait for completion; never cancel a credential update.
        if (key == "ESC" or (key == "q" and self.mode != "add")) and self.mode != "list":
            self.reset()
            return True
        if self.mode == "add":
            if key == "ENTER":
                self.preview("add", self.text)
            elif key == "BACKSPACE":
                self.text = self.text[:-1]
            elif len(key) == 1 and key in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" and len(self.text) < 64:
                self.text += key
            return True
        if self.mode == "confirm":
            if key == "y":
                action, name = self.pending
                self.pending = None
                try:
                    self.operation = clients.Operation(self.cfg, action, name)
                    self.mode, self.rows = "running", []
                except (OSError, ValueError) as exc:
                    self.error(exc)
                return True
            if key == "n":
                self.reset()
                return True
        if self.mode != "list":
            return key not in ("UP", "DOWN", "PGUP", "PGDN", "TAB", "LEFT", "RIGHT", *"12345678")
        if key in ("UP", "DOWN", "PGUP", "PGDN"):
            step = {"UP": -1, "DOWN": 1, "PGUP": -10, "PGDN": 10}[key]
            self.selected = max(0, min(len(self.users)-1, self.selected + step))
            return True
        if key in ("ENTER", "s", "a", "r", "d"):
            if self.demo:
                self.mode, self.rows = "result", ["DEMO: client operations disabled."]
            elif key == "a":
                self.mode, self.text, self.offset = "add", "", 0
            elif self.users:
                self.preview({"ENTER": "show", "s": "show", "r": "rotate", "d": "remove"}[key], self.users[self.selected])
            return True
        return False

    def render(self, width):
        from .tui import panel
        if self.mode == "list":
            rows = ["Enter/s: links + sync | a: add | r: rotate | d: remove", ""]
            rows += [("> " if i == self.selected else "  ") + name for i, name in enumerate(self.users)]
            if not self.users:
                rows += ["No clients available."]
            return panel("CLIENTS / Up-Down: select", rows, width) + (
                panel("SETUP REQUIRED", [self.problem], width) if self.problem else [])
        if self.mode == "add":
            return panel("ADD CLIENT", ["Name: " + self.text + "_", "", "Enter: preview | Esc: cancel",
                                        "Use letters, digits, dot, underscore or dash."], width)
        if self.mode == "confirm":
            return panel("CONFIRM CLIENT OPERATION", self.rows + ["", "y: apply | n/Esc: cancel"], width)
        if self.mode == "running":
            return panel("CLIENT OPERATION / RUNNING", ["Waiting for the backend to finish...",
                         "Do not close this session. The update cannot be cancelled halfway through."], width)
        return panel("CLIENT RESULT / private links", self.rows + ["", "Esc: hide result and return to clients"], width)
