"""48-hour SQLite history; one writer, short read-only reader connections."""
import contextlib
import json
import sqlite3
from pathlib import Path

from .core import RETENTION, STALE_SECONDS, number


def entities(snapshot):
    for tunnel in snapshot["tunnels"]:
        yield tunnel["id"], tunnel
        for peer in tunnel["peers"]:
            yield tunnel["id"] + "/" + peer["peer_id"], peer


def interval(previous, current):
    """A missing/reset observation is not zero traffic. Wall jumps break continuity."""
    dt = current["monotonic"] - previous["monotonic"]
    wall = current["timestamp"] - previous["timestamp"]
    return dt if previous["boot"] == current["boot"] != "unknown" and 0 < dt <= STALE_SECONDS and abs(wall - dt) < 2 else None


def delta(old, new, dt):
    if dt is None or old.get("generation") != new.get("generation"):
        return None
    if not all(type(r.get(k)) is int and r[k] >= 0 for r in (old, new) for k in ("rx", "tx")):
        return None
    if new["rx"] < old["rx"] or new["tx"] < old["tx"]:
        return None
    return new["rx"] - old["rx"], new["tx"] - old["tx"]


@contextlib.contextmanager
def reader(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        if conn.execute("PRAGMA user_version").fetchone()[0] != 1:
            raise ValueError("Unsupported history schema")
        yield conn
    finally:
        conn.close()


def latest(path):
    if not Path(path).is_file():
        return None
    with reader(path) as conn:
        row = conn.execute("SELECT value FROM metadata WHERE key='snapshot'").fetchone()
        return json.loads(row[0]) if row else None


def history(path, since, entity=None, limit=200):
    if not Path(path).is_file():
        return []
    with reader(path) as conn:
        sql = "SELECT timestamp,kind,entity,detail FROM events WHERE timestamp>=?"
        args = [since]
        if entity:
            sql += " AND (entity=? OR substr(entity,1,length(?)+1)=?||'/' OR (kind='controller_switch' AND (instr(detail,?||' -> ')=1 OR substr(detail,-length(?)-4)=' -> '||?)))"
            args += [entity] * 6
        sql += " ORDER BY timestamp DESC,id DESC LIMIT ?"
        return [dict(r) for r in conn.execute(sql, args + [limit])]


def traffic(path, entity, now, window):
    result = {"entity": entity, "window_seconds": window, "rx_bytes": None, "tx_bytes": None,
              "coverage_seconds": 0, "coverage_percent": 0, "intervals_skipped": 0,
              "boundary_estimated": False, "latest_timestamp": None}
    if not Path(path).is_file():
        return result
    with reader(path) as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT timestamp,monotonic,boot,generation,rx,tx FROM samples WHERE entity=? AND timestamp>=? AND timestamp<=? ORDER BY timestamp,id",
            (entity, now - window - STALE_SECONDS, now))]
    total_rx = total_tx = covered = 0.0
    for old, new in zip(rows, rows[1:]):
        if new["timestamp"] <= now - window:
            continue
        dt = interval(old, new)
        amounts = delta(old, new, dt)
        if amounts is None:
            result["intervals_skipped"] += 1
            continue
        overlap = min(new["timestamp"], now) - max(old["timestamp"], now - window)
        fraction = max(0, min(1, overlap / (new["timestamp"] - old["timestamp"])))
        covered += dt * fraction
        total_rx += amounts[0] * fraction
        total_tx += amounts[1] * fraction
        result["boundary_estimated"] |= fraction < 1
    if covered:
        result.update(rx_bytes=round(total_rx), tx_bytes=round(total_tx), coverage_seconds=round(covered, 2),
                      coverage_percent=round(min(100, covered / window * 100), 2))
    if rows:
        result["latest_timestamp"] = rows[-1]["timestamp"]
    return result


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=3)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA journal_size_limit=8388608")
        self.conn.execute("PRAGMA max_page_count=65536")  # 256 MiB at default 4 KiB pages
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1):
            self.conn.close()
            raise ValueError("Unsupported history schema; database left intact")
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS samples(
                id INTEGER PRIMARY KEY,timestamp REAL,monotonic REAL,boot TEXT,
                entity TEXT,generation TEXT,rx INTEGER,tx INTEGER);
            CREATE INDEX IF NOT EXISTS samples_entity_time ON samples(entity,timestamp);
            CREATE INDEX IF NOT EXISTS samples_time ON samples(timestamp);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,timestamp REAL,kind TEXT,entity TEXT,detail TEXT,
                source_id TEXT UNIQUE);
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
            PRAGMA user_version=1;
        """)
        self.last_prune = 0

    def close(self):
        self.conn.close()

    def get(self, key):
        row = self.conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def set(self, key, value):
        self.conn.execute("INSERT OR REPLACE INTO metadata VALUES (?,?)", (key, json.dumps(value, ensure_ascii=True)))

    def event(self, timestamp, kind, entity, detail, source_id=None):
        self.conn.execute("INSERT OR IGNORE INTO events(timestamp,kind,entity,detail,source_id) VALUES (?,?,?,?,?)",
                          (timestamp, kind, entity, detail, source_id))

    def save(self, snapshot, events=(), cursor=None, journal_since=None):
        old = self.get("snapshot")
        previous = dict(entities(old)) if old else {}
        dt = interval(old, snapshot) if old else None
        timestamp = snapshot["timestamp"]
        with self.conn:
            # Prune before inserts so an old, full DB can recover on restart.
            if timestamp - self.last_prune >= 60 or timestamp < self.last_prune:
                for table in ("samples", "events"):
                    self.conn.execute("DELETE FROM " + table + " WHERE timestamp<?", (timestamp - RETENTION,))
                self.last_prune = timestamp
            if old and dt is None:
                self.event(timestamp, "observation_gap", "warden", "Boot changed, clock changed, or collection gap >30s")
            for key, row in entities(snapshot):
                prior = previous.get(key)
                amounts = delta(prior, row, dt) if prior else None
                row["rx_bps"] = amounts[0] * 8 / dt if amounts else None
                row["tx_bps"] = amounts[1] * 8 / dt if amounts else None
                contiguous = bool(prior and dt is not None and prior.get("generation") == row.get("generation"))
                for field, observed in (("healthy", row.get("health") == "Healthy"), ("active", row.get("role") == "Active")):
                    start = (prior.get(field + "_since_monotonic") if contiguous else None) if prior else None
                    since = (start if number(start) else snapshot["monotonic"]) if observed else None
                    row[field + "_since_monotonic"] = since
                    row[field + "_observed_seconds"] = snapshot["monotonic"] - since if since is not None else None
                if prior:
                    for field in ("health", "role"):
                        if prior.get(field) != row.get(field):
                            self.event(timestamp, field + "_change", key, str(prior.get(field)) + " -> " + str(row.get(field)))
                    if row.get("handshake") and prior.get("handshake") != row.get("handshake"):
                        self.event(timestamp, "handshake_observed", key, "Latest handshake: " + str(row["handshake"]))
                    if dt is not None and amounts is None and (row.get("rx") is not None or row.get("tx") is not None):
                        self.event(timestamp, "counter_discontinuity", key, "Identity changed, counters reset, or previous counters unavailable")
                self.conn.execute("INSERT INTO samples(timestamp,monotonic,boot,entity,generation,rx,tx) VALUES (?,?,?,?,?,?,?)",
                                  (timestamp, snapshot["monotonic"], snapshot["boot"], key, row["generation"], row.get("rx"), row.get("tx")))
            for key in previous.keys() - dict(entities(snapshot)).keys():
                self.event(timestamp, "entity_removed", key, "Entity no longer observed")
            for event in events:
                if timestamp - RETENTION <= event["timestamp"] <= timestamp + 2:
                    self.event(**event)
            self.set("snapshot", snapshot)
            if snapshot.get("journal", {}).get("reader_version") == 2 and self.get("journal_reader_version") != 2:
                self.set("journal_cursor", None)
                self.set("journal_since", None)
            if cursor is not None:
                self.set("journal_cursor", cursor)
            if journal_since is not None:
                self.set("journal_since", journal_since)
            if snapshot.get("journal", {}).get("reader_version") == 2:
                self.set("journal_reader_version", 2)
