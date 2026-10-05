# Changelog

## 0.1.0

- First passive Ravelin observer: curses TUI, CLI/JSON, AWG/WG peers and VLESS components.
- Read-only controller-v1 AST and registry-v2 adapters; actual kernel egress selection.
- 48-hour SQLite history, per-interface/per-peer rates, coverage-aware traffic windows.
- Observed handshake/health/role changes and bounded, deduplicated controller journal events.
- Explicit stale/unknown/gap handling, secret allowlists, no network probes or mutations.
- Local installer, constrained systemd collector, synthetic demo and Linux CI.
