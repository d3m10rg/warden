# Changelog

## 0.6.5

- Fix the reverse-WSS firewall unit fingerprint: 0.6.4 calculated it using Windows
  Path formatting instead of the deployed Linux path, rejecting valid installations.
- Exercise the production fingerprint against the actual Linux unit fixture;
  reject backslash-rendered paths and modified commands before mutations.
- Keep exact helper/unit verification and all dependency guards; no server file edits.

## 0.6.4

- Support the reviewed reverse-WSS Forpost3 firewall prerequisite without stopping,
  restarting or editing it. Limit the exception to its Requires edge and channel;
  verify the installed unit/helper hashes and independent active oneshot state.
- Preserve prerequisite fingerprints across Stop/Start and reject changed files,
  unexpected coupling/drop-ins and other foreign service dependencies.
- Wait up to 90 seconds for automatic reverse-peer reconnect and HTTPS 3/3 on Start;
  roll back local startup on timeout while preserving the firewall prerequisite.

## 0.6.3

- Publish the Hysteria2 compatibility patch previously installed during Forpost1
  migration: parse the transport kind and use its service for observations and
  guarded Stop/Start. Hysteria2 Start does not require the ICMP server-reset flag.
- Preserve transport configuration, certificates, controller and service startup
  behavior; updating Warden restarts only its collector.
- Record the user's successful TUI Maintenance/Stop/Start/return acceptance on
  Forpost1 with Hysteria2 and current collector memory observations.
- Pin Linux CI to Ubuntu 24.04: ubuntu-latest moved to 26.04, where setup-python
  cannot install the supported Python 3.9 test runtime.

## 0.6.2

- Show Starting/Stopping and the ICMP Waiting for server phase in passive CLI/TUI
  observations and live backend output, without changing registry selection flags.
- Use ephemeral root-owned /run records tied to PID, process start ticks and boot;
  ignore dead/reused processes and malformed records. Progress IO cannot block rollback.
- Keep an actual Active kernel route visible over operation metadata. Database
  schema, collector sandbox, transport startup and controller behavior are unchanged.
- Record completed Ravelin acceptance and outstanding pre-1.0 checks separately.

## 0.6.1

- Require explicit `--wait-for-server-reset` for ICMP Start; preflight the bounded
  probe API before mutations. TUI Start explains and confirms the same coordination.
- After local startup, prompt for a manual reset of only the selected server's
  udp2raw transport; wait up to 90 seconds for HTTPS 3/3 with five-second probes.
  Timeout/interruption rolls back local startup; no remote commands are executed.
- Stream backend output while CLI/TUI operations run, so the reset prompt arrives
  before the wait expires. Include bounded probe diagnostics and clarify failure output.

## 0.6.0

- Explicit CLI Stop/Start and Tunnels x/s confirmation panels for registered
  ICMP/fakeTCP/WSS channels already in Maintenance; fresh healthy current exit required.
- Stop preserves unit enablement/configs and uses persistent per-unit conditions
  to prevent controller Wants and reboot from restarting the excluded channel.
- Start restores only its transport, AWG, link-dependent probe routes and source
  mark, verifies HTTPS, and keeps Maintenance until a separate return to selection.
- Installed forpostctl journal/lock/SSH baseline and rollback handle failures;
  reject changed profiles/units, foreign service dependencies, AWG hooks and custom routes.
- Stopped/Down observation; collector, database schema and VPN installation unchanged.

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
