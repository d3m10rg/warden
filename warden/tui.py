"""CPView-like keyboard console. Formatting is testable without curses."""
import json
import time

from . import __version__
from .core import STALE_SECONDS, clean
from .storage import history, latest, traffic

TABS = ("Overview", "Tunnels", "Hosts", "VLESS", "Traffic", "Events")


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


def page_lines(data, tab, selected, cfg, detail=False, demo_mode=False):
    tunnels = data["tunnels"]
    row = tunnels[min(selected, len(tunnels)-1)] if tunnels else None
    if detail and row:
        return details(row)
    if tab == 0:
        return overview(data)[1:]
    if tab == 1:
        return tunnel_table(data, selected) + ["", "Enter: peer details. Configuration/traffic counters are observed only."]
    if tab == 2:
        lines = ["Hosts: no active probes in 0.1 (planned for 0.2)", ""]
        for r in tunnels:
            lines += [f"{r['name']}: external={r.get('public', 'see peer endpoints')} internal={r.get('peer', 'see peer AllowedIPs')}",
                      "  Public/private reachability: Not tested"]
            for peer in r["peers"]:
                lines += [f"  {peer['name']} | endpoint={peer['endpoint'] or 'none'} | {peer['health']}"]
        return lines
    if tab == 3:
        return ["VLESS component observations — client session NOT tested", ""] + json.dumps(data["vless"], indent=2, ensure_ascii=True).splitlines() + [
            "", *[f"{s['id']}: {s['state']}" for s in data["services"] if "vless" in s["id"] or "nginx" in s["id"]]]
    if demo_mode:
        return ["DEMO: no database is read or created. Live collector supplies traffic history/events."]
    if tab == 4:
        if not row:
            return ["No tunnels observed."]
        lines = ["Up/Down: choose tunnel | RX/TX relative to Ravelin", ""]
        for window in (60, 3600, 86400):
            lines += format_traffic(traffic(cfg["database"], row["id"], time.time(), window)) + [""]
        return lines
    return format_history(history(cfg["database"], time.time() - 48*3600))


def run(data, cfg, demo_mode=False):
    try:
        import curses
    except ImportError:
        raise ValueError("TUI requires Python curses on Linux; use status --json here") from None

    def screen(stdscr):
        nonlocal data
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(200)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
        tab, selected, offset, detail = 0, 0, 0, False
        last_refresh = 0
        cached_key, lines = None, []
        message = ""
        while True:
            now = time.monotonic()
            if now - last_refresh >= 2 and not demo_mode:
                try:
                    fresh = latest(cfg["database"])
                    if fresh:
                        data = fresh
                    else:
                        message = "Collector history absent; initial live observation only. q: exit."
                except Exception:
                    message = "History unavailable; showing last observation."
                last_refresh = now
            selected = min(selected, max(0, len(data["tunnels"])-1))
            key = (data["timestamp"], tab, selected, detail, int(now / 10))
            if key != cached_key:
                try:
                    lines = page_lines(data, tab, selected, cfg, detail, demo_mode)
                except Exception:
                    lines = ["History unavailable; check collector status and permissions."]
                cached_key = key
            height, width = stdscr.getmaxyx()
            stdscr.erase()

            def put(y, text, attr=0):
                if 0 <= y < height and width > 1:
                    try:
                        stdscr.addnstr(y, 0, clean(text, 2000), width-1, attr)
                    except curses.error:
                        pass

            title = f"WARDEN {__version__} | {'DEMO' if demo_mode else 'READ ONLY'} | {age_line(data)}"
            put(0, title, curses.A_BOLD | (curses.color_pair(1) if curses.has_colors() else 0))
            put(1, "  ".join((f"[{i+1} {name}]" if i == tab else f" {i+1} {name} ") for i, name in enumerate(TABS)), curses.A_REVERSE)
            if height < 8 or width < 60:
                put(3, "Enlarge terminal to at least 60 columns / 8 rows.")
            else:
                capacity = height-5
                offset = min(offset, max(0, len(lines)-capacity))
                for i, line in enumerate(lines[offset:offset+capacity]):
                    color = 3 if "Down" in line or "Failed" in line else 2 if "Unknown" in line or line.startswith("!") else 4 if "Healthy" in line else 0
                    put(i+3, line, curses.color_pair(color) if curses.has_colors() else 0)
            put(height-2, message, curses.A_BOLD)
            put(height-1, "1-6/Tab: view  arrows: select/scroll  PgUp/PgDn  Enter: details  Esc: back  q: quit", curses.A_REVERSE)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord('q'), ord('Q')):
                break
            if ord('1') <= key <= ord('6'):
                tab, offset, detail = key-ord('1'), 0, False
            elif key in (9, curses.KEY_RIGHT, curses.KEY_LEFT):
                tab = (tab + (-1 if key == curses.KEY_LEFT else 1)) % len(TABS)
                offset, detail = 0, False
            elif key in (10, 13, curses.KEY_ENTER) and tab in (0, 1, 4):
                detail, offset = not detail, 0
            elif key == 27:
                detail, offset = False, 0
            elif key in (curses.KEY_DOWN, curses.KEY_UP):
                step = 1 if key == curses.KEY_DOWN else -1
                if not detail and tab in (1, 4):
                    selected = max(0, min(len(data["tunnels"])-1, selected+step))
                else:
                    offset = max(0, offset+step)
            elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE):
                offset = max(0, offset + (1 if key == curses.KEY_NPAGE else -1) * max(1, height-5))
    try:
        curses.wrapper(screen)
    except curses.error:
        raise ValueError("Cannot initialize terminal; use warden status or a compatible TERM") from None
