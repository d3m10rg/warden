"""CPView-like keyboard console. Formatting is testable without curses."""
import json
import signal
import subprocess
import sys
import textwrap
import time

from . import __version__
from .core import STALE_SECONDS, clean
from .storage import history, latest, traffic

TABS = ("Overview", "Tunnels", "Hosts", "VLESS", "Traffic", "Events", "Diagnostics", "Clients")


def amount(value, suffix="B"):
    if value is None:
        return "N/A"
    for unit in ("", "Ki", "Mi", "Gi", "Ti"):
        if abs(value) < 1024 or unit == "Ti":
            return f"{value:.1f}{unit}{suffix}"
        value /= 1024


def elapsed(value):
    if value is None:
        return "N/A"
    return f"{int(value)//3600}h {(int(value)%3600)//60}m {int(value)%60}s"


def age_line(data):
    age = time.time() - data["timestamp"]
    return f"Data age {age:.0f}s | " + ("STALE — current state unknown" if not 0 <= age <= STALE_SECONDS else "fresh observation")


def tunnel_table(data, selected=None):
    lines = ["  ID               Interface    Role     Health      RX bit/s      TX bit/s"]
    for index, row in enumerate(data["tunnels"]):
        cursor = ">" if index == selected else " "
        lines.append(f"{cursor} {row['id'][:16]:16} {row['interface'][:12]:12} {row['role'][:8]:8} {row['health'][:11]:11} {amount(row.get('rx_bps'), 'b/s'):>12} {amount(row.get('tx_bps'), 'b/s'):>12}")
    return lines


def overview(data):
    controller = data["controller"]
    return [f"WARDEN {__version__} | READ ONLY | {age_line(data)}",
            f"Egress: {controller['active']} | Controller: {controller['version']} | probes fresh: {controller['fresh']}",
            f"Guards: unreachable={controller.get('unreachable_guard')} local-source-rule={controller.get('local_source_rule')}",
            "", *tunnel_table(data), "", "Services:",
            *[f"  {row['id']}: {row['state']}" for row in data["services"]],
            "", *["! " + warning for warning in data["warnings"]]]


def details(row):
    lines = [row.get("name", row["id"]) + " / " + row["interface"],
             f"{row['kind']} | {row['role']} | {row['health']}", row["reason"],
             "Note: " + row.get("note", ""),
             "Observed healthy: " + elapsed(row.get("healthy_observed_seconds")),
             "Observed active:  " + elapsed(row.get("active_observed_seconds")),
             "Rank: " + str(row.get("rank") if row.get("rank") is not None else "N/A (not reported)"),
             "Transport: " + clean(row.get("transport", "unmanaged")) +
             " | enabled=" + str(row.get("enabled", "N/A")) + " | retired=" + str(row.get("retired", "N/A")),
             f"Interface totals RX={amount(row.get('rx'))} TX={amount(row.get('tx'))}",
             "", "Peers (handshake is not an end-to-end health check):"]
    for probe in row.get("probe_details", []):
        lines += [f"Controller probe ({'fresh' if row.get('probes_fresh') else 'STALE'}): "
                  f"{probe['target']} | {probe['stage']} / {probe['reason']} | {probe['elapsed_ms']} ms"]
    for peer in row["peers"]:
        lines += [f"  {peer['peer_id']}  {clean(peer['name'])}",
                  f"    endpoint={peer['endpoint'] or 'none'} | {peer['health']} | handshake age={elapsed(peer['handshake_age_seconds'])}",
                  f"    RX={amount(peer['rx'])} TX={amount(peer['tx'])}"]
    return lines


def format_history(rows):
    return ["Time                 Event                    Entity                  Detail"] + [
        f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['timestamp']))}  {r['kind']:<24} {r['entity']:<23} {clean(r['detail'])}"
        for r in rows] if rows else ["No recorded events in this period."]


def format_traffic(row):
    return [f"{row['entity']} | window {elapsed(row['window_seconds'])}",
            f"RX {amount(row['rx_bytes'])} | TX {amount(row['tx_bytes'])}",
            f"Coverage: {row['coverage_percent']:.1f}% ({elapsed(row['coverage_seconds'])}) | skipped intervals: {row['intervals_skipped']}",
            "Window edge estimated: " + str(row["boundary_estimated"])]


def panel(title, rows, width):
    """ASCII only borders; fit even narrow SSH terminals."""
    inner = max(1, width-4)
    border = "+- " + title[:max(0, width-6)] + " "
    border = border[:width-1].ljust(width-1, "-") + "+"
    body = []
    for row in rows:
        row = clean(row, 4000)
        for text in textwrap.wrap(row, inner, replace_whitespace=False, drop_whitespace=False) or [""]:
            body.append("| " + text.ljust(inner) + " |")
    return [border, *body, "+" + "-"*(width-2) + "+"]


def compact_tunnels(data, selected=None):
    rows = ["  Tunnel       Interface  Role    Health        RX bit/s    TX bit/s",
            "  ------------ ---------- ------- ----------- ----------- -----------"]
    for i, r in enumerate(data["tunnels"]):
        rows.append(f"{'>' if selected == i else ' '} {r['id'][:12]:12} {r['interface'][:10]:10} "
                    f"{r['role'][:7]:7} {r['health'][:11]:11} {amount(r.get('rx_bps'), 'b/s'):>11} {amount(r.get('tx_bps'), 'b/s'):>11}")
    return rows


def page_lines(data, tab, selected, cfg, detail=False, demo_mode=False, width=100):
    tunnels = data["tunnels"]
    row = tunnels[min(selected, len(tunnels)-1)] if tunnels else None
    if detail and row:
        return panel("TUNNEL / " + row["id"], details(row), width)
    if tab == 0:
        c = data["controller"]
        return (panel("EGRESS / CONTROLLER", [
            f"Active: {c['active']}    Backend: {c['version']}    Probes fresh: {c['fresh']}",
            f"Unreachable guard: {c.get('unreachable_guard')}    Local source rule: {c.get('local_source_rule')}"], width) +
            panel("TUNNELS", compact_tunnels(data), width) +
            panel("SERVICES", [f"{r['id']:<44} | {r['state']}" for r in data["services"]], width) +
            (panel("NOTICES", data["warnings"], width) if data["warnings"] else []))
    if tab == 1:
        return panel("TUNNELS / Enter: details", compact_tunnels(data, selected), width)
    if tab == 2:
        lines = ["Use 7 Diagnostics for explicit external/internal ping.", ""]
        for r in tunnels:
            lines += [f"{r['name']}: external={r.get('public', 'see peer endpoints')} internal={r.get('peer', 'see peer AllowedIPs')}",
                      "  Public/private reachability: Not tested"]
            for peer in r["peers"]:
                lines += [f"  {peer['name']} | endpoint={peer['endpoint'] or 'none'} | {peer['health']}"]
        return panel("HOSTS / observations", lines, width)
    if tab == 3:
        v = data["vless"]
        return panel("VLESS / component observations", ["Client session: NOT TESTED",
            f"Configured users: {v.get('users', 'N/A')}    Direct outbounds: {v.get('direct_outbounds', 'N/A')}",
            f"Marked outbounds: {v.get('marked_outbounds', 'N/A')}", "",
            *[f"Listener {r.get('address')}:{r.get('port')} | {r.get('transport', '')} | listening={r.get('listening', 'N/A')}" for r in v.get("listeners", [])],
            "", *[f"{s['id']}: {s['state']}" for s in data["services"] if "vless" in s["id"] or "nginx" in s["id"]]], width)
    if tab == 6:
        return panel("DIAGNOSTICS / " + (row["id"] if row else "no tunnel"), [
            "Up/Down: select tunnel. Every network test needs preview + y.",
            "i: internal ping   e: external ping   h: HTTPS   s: speed",
            "d: passive doctor report    Esc: cancel running test",
            "Speed: 5s, 5 Mbit/s, upload; configure a prepared server first.",
            "Results describe the test time; they do not change failover."], width)
    if tab == 7:
        from .clients_view import ClientsView
        view = ClientsView(cfg, demo_mode)
        view.refresh()
        return view.render(width)
    if demo_mode:
        return panel("DEMO", ["No database reads or writes; history supplied by live collector."], width)
    if tab == 4:
        if not row:
            return ["No tunnels observed."]
        lines = ["Up/Down: choose tunnel | RX/TX relative to Ravelin", ""]
        for window in (60, 3600, 86400):
            lines += format_traffic(traffic(cfg["database"], row["id"], time.time(), window)) + [""]
        return panel("TRAFFIC / " + row["id"], lines, width)
    return panel("EVENTS / last 48 hours", format_history(history(cfg["database"], time.time() - 48*3600)), width)


def frame(data, lines, width, height, tab, offset=0, message="", demo_mode=False):
    if width < 60 or height < 16:
        return ["WARDEN: enlarge terminal to 60 columns / 16 rows."]
    age = time.time() - data["timestamp"]
    freshness = "FRESH" if 0 <= age <= STALE_SECONDS else "STALE"
    title = f"WARDEN {__version__} | {'DEMO' if demo_mode else 'MONITOR'} | age {age:.0f}s | {freshness}"
    nav = [" ".join(f"[{i+1} {name}]" if i == tab else f" {i+1} {name} "
                    for i, name in enumerate(TABS) if start <= i < start+4) for start in (0, 4)]
    header = panel(title, nav, width)
    capacity = max(1, height-len(header)-4)
    content = lines[offset:offset+capacity]
    content += [" " * width] * (capacity-len(content))
    footer = panel(f"{TABS[tab]} | lines {offset+1}-{min(len(lines), offset+capacity)}/{len(lines)}", [
        clean(message or "1-8/Tab: view | arrows: move | Enter: details/menu", max(1, width-4)),
        "PgUp/PgDn: scroll | Esc: back/cancel | q: quit"], width)
    return header + content + footer


def run(data, cfg, demo_mode=False, config_path="/etc/warden/config.json", initial_tab=0):
    try:
        import curses
    except ImportError:
        raise ValueError("TUI requires Python curses on Linux; use status --json here") from None

    child = None
    from .clients_view import ClientsView
    clients_view = ClientsView(cfg, demo_mode)
    priority_view = None

    def cancel_child():
        nonlocal child
        if child is not None:
            if child.poll() is None:
                child.terminate()
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
            child = None

    def screen(stdscr):
        nonlocal data, child, priority_view
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(200)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for i, color in enumerate((curses.COLOR_CYAN, curses.COLOR_YELLOW, curses.COLOR_RED, curses.COLOR_GREEN), 1):
                curses.init_pair(i, color, -1)
        tab, selected, offset, detail = initial_tab, 0, 0, False
        last_refresh = 0
        cached_key, lines = None, []
        message, diagnostic_lines = "", []
        pending, action = None, None

        def start(command_name, entity, scope=None, execute=False, expected=None):
            nonlocal child, action, message, pending
            argv = [sys.executable, "-B", "-m", "warden", "--config", config_path, command_name]
            if command_name != "doctor":
                argv.append(entity)
            if scope:
                argv += ["--scope", scope]
            if execute:
                argv.append("--run")
            if expected is not None:
                argv += ["--expect-plan", json.dumps({k: v for k, v in expected.items() if k != "timestamp"})]
            argv.append("--json")
            from pathlib import Path
            child = subprocess.Popen(argv, cwd=str(Path(__file__).resolve().parent.parent),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            action = (command_name, entity, scope, execute)
            pending = None
            message = "Running diagnostic; Esc cancels" if execute else "Reading live state and checking route..."

        while True:
            now = time.monotonic()
            if clients_view.poll():
                cached_key, offset = None, 0
            if priority_view and priority_view.poll():
                cached_key, offset = None, 0
            if child is not None and child.poll() is not None:
                stdout, stderr = child.communicate()
                child = None
                try:
                    result = json.loads(stdout)
                    from .diagnostics import format_result
                    diagnostic_lines = (json.dumps(result, indent=2).splitlines() if action[0] == "doctor"
                                        else format_result(result))
                    if action[0] != "doctor" and not action[3]:
                        pending = (action, result)
                        message = "Preview ready: y sends traffic | Esc discards"
                    else:
                        message = "Finished at " + time.strftime("%H:%M:%S") + "; result is not refreshed automatically"
                except (ValueError, KeyError, TypeError):
                    diagnostic_lines = [clean(stderr, 200) or "Diagnostic unavailable"]
                    message = "No result; review diagnostic message"
                cached_key = None
            if now - last_refresh >= 2 and not demo_mode:
                try:
                    fresh = latest(cfg["database"])
                    if fresh:
                        data = fresh
                    elif not message:
                        message = "No collector history; showing initial observation"
                except Exception:
                    message = "History unavailable; showing last observation"
                last_refresh = now
            selected = min(selected, max(0, len(data["tunnels"])-1))
            height, width = stdscr.getmaxyx()
            # Leave last column unused for terminals with auto-wrap.
            columns = max(10, width-1)
            key = (data["timestamp"], tab, selected, detail, int(now / 10), columns)
            if key != cached_key:
                try:
                    if priority_view:
                        lines = priority_view.render(columns)
                    elif tab == 7:
                        if clients_view.mode == "list":
                            clients_view.refresh()
                        lines = clients_view.render(columns)
                    else:
                        lines = page_lines(data, tab, selected, cfg, detail, demo_mode, columns)
                    if tab == 6 and diagnostic_lines:
                        lines += panel("LAST DIAGNOSTIC", diagnostic_lines, columns)
                except Exception:
                    lines = panel("NOTICE", ["History unavailable; check collector status and permissions."], columns)
                cached_key = key
            capacity = max(1, height-8)
            if tab == 1 and not detail and priority_view is None:
                offset = max(min(offset, selected+3), selected+4-capacity)
            if tab == 7 and clients_view.mode == "list":
                offset = max(min(offset, clients_view.selected+3), clients_view.selected+4-capacity)
            offset = min(max(0, offset), max(0, len(lines)-capacity))
            stdscr.erase()
            footer_message = message
            if tab == 1:
                footer_message = "Enter: details | p: priority | Up/Down: select"
            if priority_view:
                footer_message = "Operation running; wait" if priority_view.operation else "PgUp/PgDn: scroll | Esc: return"
            if tab == 7:
                footer_message = ("Up/Down: select | Enter/s: links | a/r/d: manage" if clients_view.mode == "list" else
                                  "Operation running; wait for completion" if clients_view.operation else
                                  "PgUp/PgDn: scroll | Esc: back")
            rendered = frame(data, lines, columns, height, tab, offset, footer_message, demo_mode)
            for y, line in enumerate(rendered[:height]):
                color = 1 if line.startswith("+") else 3 if "Down" in line or "Failed" in line else 2 if "Unknown" in line or "STALE" in line else 4 if "Healthy" in line else 0
                attr = curses.color_pair(color) if curses.has_colors() else 0
                if line.startswith("| >") or y in (1, 2):
                    attr |= curses.A_REVERSE
                try:
                    stdscr.addnstr(y, 0, clean(line, 4000), max(0, width-1), attr)
                except curses.error:
                    pass
            stdscr.refresh()
            key = stdscr.getch()
            if tab == 7 or priority_view:
                event = {27: "ESC", 10: "ENTER", 13: "ENTER", curses.KEY_ENTER: "ENTER",
                         curses.KEY_UP: "UP", curses.KEY_DOWN: "DOWN", curses.KEY_PPAGE: "PGUP",
                         curses.KEY_NPAGE: "PGDN", curses.KEY_LEFT: "LEFT", curses.KEY_RIGHT: "RIGHT",
                         9: "TAB", curses.KEY_BACKSPACE: "BACKSPACE", 127: "BACKSPACE", 8: "BACKSPACE"}.get(
                             key, chr(key) if 0 <= key <= 255 else "")
                if priority_view:
                    if key != -1 and priority_view.handle(event):
                        cached_key = None
                        if priority_view.mode == "closed":
                            priority_view, offset = None, 0
                        continue
                elif child is not None and event in ("ENTER", "s", "a", "r", "d", "y"):
                    message = "Wait for diagnostic completion or cancel with Esc"
                    continue
                elif key != -1 and clients_view.handle(event):
                    cached_key = None
                    if clients_view.mode != "list":
                        offset = clients_view.offset
                    continue
            if tab == 1 and key == ord('p') and priority_view is None:
                if child is None and data["tunnels"]:
                    from .channel_admin import PriorityView
                    priority_view = PriorityView(cfg, data["tunnels"][selected]["id"], demo_mode)
                    offset, cached_key = 0, None
                continue
            if key in (ord('q'), ord('Q')):
                break
            if key == 27:
                cancel_child()
                pending, detail, offset, message = None, False, 0, ""
            elif tab == 6 and key == ord('y') and pending and child is None:
                confirmed, expected = pending
                start(confirmed[0], confirmed[1], confirmed[2], execute=True, expected=expected)
            elif tab == 6 and key in map(ord, "iehsd") and child is None:
                if demo_mode:
                    message = "DEMO: active diagnostics disabled; no host inspection"
                elif data["tunnels"] or key == ord('d'):
                    entity = data["tunnels"][selected]["id"] if data["tunnels"] else ""
                    command_name, scope = {ord('i'): ("ping", "internal"), ord('e'): ("ping", "external"),
                        ord('h'): ("https", None), ord('s'): ("speed", None), ord('d'): ("doctor", None)}[key]
                    diagnostic_lines, offset, cached_key = [], 0, None
                    start(command_name, entity, scope)
            elif ord('1') <= key <= ord('8'):
                clients_view.reset()
                tab, offset, detail, pending = key-ord('1'), 0, False, None
                if child is None:
                    message = ""
            elif key in (9, curses.KEY_RIGHT, curses.KEY_LEFT):
                clients_view.reset()
                tab = (tab + (-1 if key == curses.KEY_LEFT else 1)) % len(TABS)
                offset, detail, pending = 0, False, None
                if child is None:
                    message = ""
            elif key in (10, 13, curses.KEY_ENTER) and tab in (0, 1, 4):
                detail, offset = not detail, 0
            elif key in (curses.KEY_DOWN, curses.KEY_UP):
                step = 1 if key == curses.KEY_DOWN else -1
                if not detail and tab in (1, 4, 6):
                    selected = max(0, min(len(data["tunnels"])-1, selected+step))
                    pending = None
                    if child is None:
                        message = ""
                else:
                    offset = max(0, offset+step)
            elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE):
                offset = max(0, offset + (1 if key == curses.KEY_NPAGE else -1) * capacity)
    def interrupt(*_):
        if clients_view.operation is None and not (priority_view and priority_view.operation):
            raise KeyboardInterrupt()

    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {sig: signal.signal(sig, interrupt) for sig in signals}
    try:
        curses.wrapper(screen)
    except curses.error:
        raise ValueError("Cannot initialize terminal; use warden status or a compatible TERM") from None
    finally:
        # Never terminate the client backend on Esc, resize, Ctrl-C or TUI error.
        if clients_view.operation:
            clients_view.operation.wait()
        if priority_view and priority_view.operation:
            priority_view.operation.wait()
        clients_view.reset()
        cancel_child()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
