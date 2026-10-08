# Changelog

## 0.2.1

- Fix journal direction: `--grep` with `-n 500` implicitly reversed results.
  Read the first 500 unit records forward, advance over ordinary service messages,
  and retain only validated switch events. No grep scan for rare switch messages.
- Rebuild the retained 48-hour switch history once in bounded batches after the
  upgrade, preserving existing observations and deduplicating by journal cursor.
- Report catching-up, timeout, command failure, invalid entries and cursor recovery
  separately. Retry errors after 60 seconds, backing off to 10 minutes; passive
  observations continue. Only an explicit cursor error triggers time-based recovery.
- Doctor includes the collector's recorded journal status and snapshot age instead
  of implying that live observation warnings cover the switch journal.
- Keep the 128 MiB memory limit, VPN configuration and controller unchanged. Lower
  cache pressure on Ravelin must be verified after the forward reader catches up.

## 0.2.0

- ASCII panel TUI with persistent navigation, selected rows, compact service/VLESS
  views and a Diagnostics tab. Preview, confirmation and cancellation stay in TUI;
  live observations keep refreshing during diagnostics.
- Explicit IPv4 internal/external ping, controller-derived HTTPS target with TLS
  verification, and opt-in iperf3 to a configured server. Defaults: three pings,
  five-second HTTPS budget, five-second single-stream 5 Mbit/s speed test.
- Fresh route/source/interface checks, socket device binding, HTTPS probe-table
  guard checks and one diagnostic process at a time. No DNS/proxy/redirect fallback.
  Confirmed TUI plans are rejected if their target or route changes before execution.
- Passive allowlisted doctor report without addresses, peer IDs or credentials.
- Collector remains passive with unchanged systemd sandbox, schema 1 and 48-hour
  retention. No controller migration, network mutations, automatic tests or package
  installation. Diagnostics are session-only and do not change failover health.

## 0.1.1

- Treat clean `journalctl --grep` exit 1 with no matching entries as an empty
  switch history, not a journal-read failure. Permission errors, stderr diagnostics,
  invalid cursors, unexpected output and timeouts still produce a warning.
- Empty successful reads now advance the existing journal time watermark rather
  than repeatedly scanning the full 48-hour range on installations with no switches.
- Installation marker records the installed version automatically. Database schema,
  systemd sandbox and VPN/controller configuration are unchanged.

## 0.1.0

- First passive Ravelin observer: curses TUI, CLI/JSON, AWG/WG peers and VLESS components.
- Read-only controller-v1 AST and registry-v2 adapters; actual kernel egress selection.
- 48-hour SQLite history, per-interface/per-peer rates, coverage-aware traffic windows.
- Observed handshake/health/role changes and bounded, deduplicated controller journal events.
- Explicit stale/unknown/gap handling, secret allowlists, no network probes or mutations.
- Local installer, constrained systemd collector, synthetic demo and Linux CI.
