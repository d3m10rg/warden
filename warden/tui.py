"""CPView-like keyboard console. Formatting is testable without curses."""
import json
import subprocess
import sys
import textwrap
import time

from . import __version__
from .core import STALE_SECONDS, clean
from .storage import history, latest, traffic

TABS = ("Overview", "Tunnels", "Hosts", "VLESS", "Traffic", "Events", "Diagnostics")


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
             "Rank: " + str(row.get("rank", "N/A")) + " (v1 has fixed controller policy)",
             f"Interface totals RX={amount(row.get('rx'))} TX={amount(row.get('tx'))}",
             "", "Peers (handshake is not an end-to-end health check):"]
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
        message or "1-7/Tab: view | arrows: select/scroll | Enter: details",
        "PgUp/PgDn: scroll | Esc: back/cancel | q: quit"], width)
    return header + content + footer


def run(data, cfg, demo_mode=False, config_path="/etc/warden/config.json"):
    try:
        import curses
    except ImportError:
        raise ValueError("TUI requires Python curses on Linux; use status --json here") from None

    child = None

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
        nonlocal data, child
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(200)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            for i, color in enumerate((curses.COLOR_CYAN, curses.COLOR_YELLOW, curses.COLOR_RED, curses.COLOR_GREEN), 1):
                curses.init_pair(i, color, -1)
        tab, selected, offset, detail = 0, 0, 0, False
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
                    lines = page_lines(data, tab, selected, cfg, detail, demo_mode, columns)
                    if tab == 6 and diagnostic_lines:
                        lines += panel("LAST DIAGNOSTIC", diagnostic_lines, columns)
                except Exception:
                    lines = panel("NOTICE", ["History unavailable; check collector status and permissions."], columns)
                cached_key = key
            capacity = max(1, height-8)
            if tab == 1 and not detail:
                offset = max(min(offset, selected+3), selected+4-capacity)
            offset = min(max(0, offset), max(0, len(lines)-capacity))
            stdscr.erase()
            rendered = frame(data, lines, columns, height, tab, offset, message, demo_mode)
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
            elif ord('1') <= key <= ord('7'):
                tab, offset, detail, pending = key-ord('1'), 0, False, None
                if child is None:
                    message = ""
            elif key in (9, curses.KEY_RIGHT, curses.KEY_LEFT):
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
    try:
        curses.wrapper(screen)
    except curses.error:
        raise ValueError("Cannot initialize terminal; use warden status or a compatible TERM") from None
    finally:
        cancel_child()
