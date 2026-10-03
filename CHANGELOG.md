# Changelog

## 0.2.1 — 2026-10-03

Fixes from checking the HTA display of a real workstation collection against the raw EVTX (Get-WinEvent ground truth).

### Added
- **Remote access / RMM software detection** (T1219): Splashtop (incl. SOS on-demand), AnyDesk,
  TeamViewer, ScreenConnect, Atera, RustDesk, NetSupport, LogMeIn, GoTo, Kaseya, N-able, Zoho,
  MeshCentral, VNC family, Radmin, SimpleHelp, BeyondTrust and others, from service installs and
  process starts. High when the binary runs from a temp / user-writable folder or appears during an
  inbound remote session; the finding gives install count, first and most recent install.
- **Per-host time zones**: `--tz auto` (now the default, also in the HTA) reads each host's UTC
  offset from System event 6013 for the after-hours rule; hosts without 6013 fall back to UTC.
  Fixed offsets (`UTC+08:00`) are accepted. The Hosts pivot shows each host's zone.
- **Outbound RDP enrichment**: the 4648 credential hand-off after each connection supplies the
  acting user, the credentials used and the target's name (e.g. `10.10.20.33 (SQL01.contoso.local)` with
  `contoso\administrator`). New session columns `TargetHostName`, `CredentialsUsed`.
- Account names resolved from SIDs for events that carry only a SID (7045 installer, WinRM 91).

### Fixed
- WinRM 161 client errors were shown as failed authentications (red rows, Hosts "Failed").
- Hosts / Users / IP pivots counted the host's own outbound RDP as RDP to it; now `RdpInbound`
  and `RdpOutbound` are separate.
- One elevated interactive logon was counted up to four times as "Successful" (split-token 4624
  pair, 4672, LSM 21) and twice as "Privileged"; 4672 no longer counts as a success.
- Routine 4648s by the computer account against the machine itself (DWM, UMFD, interactive
  logon completion, scheduled tasks) inflated account counts and suspicion scores; they are now
  dropped as noise, and system accounts are never ranked as suspicious.
- Separate RDP connection attempts to the same host within five minutes were merged; each attempt
  is now its own session and the finding counts attempts.
- HTA overview and source pill showed the output folder name instead of the host; the HTA
  defaulted the after-hours zone to the analysis machine's zone.
- Velociraptor `%25`-encoded channel names (`%254Operational`) were not decoded in the import log.
- HTA output under `_Processed\` and `IOC.txt` are now git-ignored (case data).

### Second review pass (workstation results, 2026-10-03)

Added:
- **Remote hosts** pivot (`remotehosts.csv`, HTA tab): one row per system the collected hosts
  connected to, from outbound sessions and 4648 targets, with an address and its resolved name
  merged (`10.10.20.33` / `SQL01.contoso.local`), technique counts, source hosts, users, inferred
  users, credentials used, and whether that system's own logs are in the evidence. The HTA
  **Hosts** tab is now **Local hosts**.
- **Failed console logons followed by success** (T1110): 3+ bad passwords at the keyboard
  (logon types 2 / 7 / 11) then a success for the same account. Low (Medium from 10). Notes cached
  credentials (no domain controller reachable) and remote-access software already on the host,
  whose sessions log as console logons.
- **Inferred user** on outbound sessions with no account in the logs, only when exactly one
  account logged on interactively to that host in the evidence. New `InferredUser` session
  column; `User` stays empty and `Evidence` states the basis; the finding says "likely ... (inferred)".
- HTA: sort button on every column header of every tab; the Remote sessions host filter also
  lists remote targets (address with resolved name and session count) and matches either side of
  a connection; a host that does not exist on the tab you switch to is cleared; the detail card
  closes when you switch tabs.
- HTA **Known hosts…**: map IP addresses to host names (typed, pasted, loaded from a CSV / hosts
  file, or accepted from names the logs resolved, e.g. 4648 target servers). Names appear as labels
  next to the IPs in every table, the detail card, the host filter, the overview and case notes,
  and are searchable. Display only: engine CSVs and exports keep the logged values. Saved per
  results folder as `knownhosts.csv`.
- HTA: the IOC editor is a popup, and the **IOCs (n)…** button shows how many terms are active.
- HTA: one date window: the control panel's engine window and the view filter above the tables
  stay in sync (either box updates the other; loading results fills both with that run's window;
  `/from` `/to` set both). Widening it past the loaded run's window says to process again.
- **Activity** column on events / timeline (`Logon`, `Logon failed`, `Logoff`, `Disconnect`,
  `Reconnect`, `Boot`, `Shutdown`, `Restart`, `Unexpected shutdown`), shown in the HTA timeline as
  square labels next to the technique pills, with the logon type (`Logon · cached`). Results from
  an older engine get logon / logoff labels derived from the event id.
- **Power events** imported: System 6005 (boot), 6006 (clean shutdown), 6008 (unexpected
  shutdown), Kernel-Power 41, User32 1074 (who / which process initiated a restart or power-off,
  shutdown type recognised in English, Chinese, Japanese, Korean, German, French, Spanish,
  Italian), Security 4608 / 4609 / 1100. Kernel-General 12 / 13 are not read: their ids collide
  with high-volume Sysmon registry events and 6005 / 6006 mark the same moments.
- **Manual**: `docs/manual.html` with screenshots of a fictional incident; the HTA's Help opens it.

Fixed:
- The outbound RDP finding listed one target twice (`10.10.20.33 x17`, `10.10.20.33 (SQL01.contoso.local) x3`);
  attempts are now grouped per destination with its name, and per-account counts are shown.
- WinRM 161 / 142 client errors outside a session (local agents polling) filled half the triage
  timeline; they are in `events.csv` only.
- Users: 4648 hand-offs were counted only for the credentials' owner. `Explicit` is replaced by
  `UsedOthersCreds` (the account that used them) and `CredsUsedByOthers` (the owner); both score.
- The after-hours finding names the weekday and the reason (`Saturday 2026-09-12 (weekend; ...)`).
- Failed logons carry the NULL SID (S-1-0-0) for the target account, which classified every
  failure-only account as a system account (listed, scored 0) and hid console failures from rules.
  The NULL SID no longer overrides a real account name.
- A SYSTEM row came from one shutdown-time service-logon failure (0xC00000DC, LSA not ready);
  system-account failures with that status are dropped as noise.
- Events that carry only a well-known SID (7045 installs by SYSTEM) show `SYSTEM` / `NT AUTHORITY`
  in the CSV and HTML instead of a blank user.
- Remote access / RMM software (Splashtop...) was counted as `RemoteExec`; it has its own
  `RemoteAccessTool` column on Users and Local hosts and its own score weight.
- **HTA never captured the engine's exit code**: the runner wrote the marker with
  `echo EXITCODE=%ERRORLEVEL%> log`, and cmd reads a single digit before `>` as a handle
  redirection (`0>`), so the line was dropped for every exit code. Failures were therefore
  invisible (the old HTA accepted any run that left a `summary.json`) and the false "Build
  failed" message came from the same pattern. The marker is now `(echo EXITCODE=…)> log`, and a
  run without a marker counts only if it published a `summary.json` during this run.

Removed:
- HTA **Build engine** button (engine updates ship with the app).

### External code review (2026-10-03) — all nine findings reproduced and fixed

- **HTA script injection (P1)**: evidence values (e.g. a failed-logon user name `&#39;);…`) placed in
  inline click handlers were JavaScript-escaped but not HTML-attribute-encoded, so entity decoding
  turned them into code. `jsq` now JavaScript-escapes, then attribute-encodes; ten hostile
  payloads round-trip as literal strings.
- **Corrupt input accepted (P1)**: a file that is not an event log read as an empty log with no
  error. The per-log query status is now checked; the file is marked failed, and when no input can
  be read the engine exits **4** without writing results.
- **Failed reruns shown as success (P1)**: the engine now stages results and publishes them only
  on success (`summary.json` last; a results file open in another program aborts the publish and
  leaves the previous results intact). The HTA loads results only for exit code 0 with a
  `summary.json` from this run; otherwise it says the folder holds the previous run and does not
  load or record it.
- **Outbound hand-off mis-attribution (P2)**: a 4648 attaches to an outbound connection only when
  its technique and destination fit; a name-for-address match (RDP: IP in the client log, server
  name in the CredSSP 4648) is Medium, High only when the same pairing recurs on two or more
  connections, and withdrawn when the address or name is paired with something else.
- **Simultaneous shells merged (P2)**: remote shells, service execution and admin-share drops are
  partitioned by logon session before time; events without one join only the single matching
  session.
- **Logon-id reuse across reboots (P2)**: boot events end every logon-id correlation (process
  filter, RDP session building, in-session process window); a closed RDP session accepts only
  logoff bookkeeping. A reconnect's short-lived authentication logon no longer closes the session
  (the old code did, which split and mislabelled reconnected sessions).
- **Share read reported as write (P2)**: 5145 executable / PSEXESVC drops need requested write rights
  (WriteData / AppendData / GENERIC_WRITE…); denied access (audit failure) is context only; Impacket
  output files still count on read. Rule renamed **Write access to executable on admin share**.
- **Different accounts with one name (P2)**: account comparisons are domain-aware (NetBIOS / FQDN
  forms match, a missing domain matches either). Failed-then-success, password spray, explicit
  credentials and the Users pivot use it; the Users pivot splits a name into `DOMAIN\user` rows only
  when it is used by accounts of different domains, and the HTA user pin respects the domain.
- **Quadratic correlation (P2)**: time-window lookups are binary searches and RDP session lookups are
  indexed; 32,000 outbound attempts correlate in ~0.2 s (was 4.5 s). The failed-then-success rule's
  look-back is bounded by its window.

On a 12-host test collection: RDP sessions that had been stitched across reboots (up to 2,217
days long) are cut at the boot, reconnects stay in their session, and one "Failed logons followed
by success" (APP01\Administrator failing, CONTOSO\Administrator succeeding) is no longer reported.

## 0.2.0 — 2026-10-02

### Added
- **HTA front end** (`hta/LoginActivityTriage.hta`) in the Hayabusa / PECmd wrapper family:
  `_Processed\<host>\` output, `runinfo.json` provenance with triage summary, toolkit `IOC.txt`,
  Artifact-Finder command line, self-update, engine build / download, Timeline Explorer hand-off.
- **Engine** `LoginActivityTriageCli.exe`: folder, file or live-log input; CSV + JSON + HTML output.
- **Remote-session stitching**: RDP, PsExec and clones, Impacket psexec / smbexec / wmiexec /
  dcomexec / atexec, PowerShell Remoting, WinRS, WMI, DCOM, remote tasks and services, admin-share
  drops, outbound activity.
- Normalisers for System (7045, 7036, 7040, 104), WinRM, Windows PowerShell + PowerShell/Operational,
  Sysmon (1, 17, 18), RdpCoreTS, RDPClient, and 26 more Security event IDs (4634, 4647, 4688,
  4697, 4698/4699/4702, 4720–4726, 4728/4732/4756, 4740, 4768/4769/4771/4776, 4778/4779,
  5140/5145, 1102).
- Fields: logon id / linked logon id, subject account, session id, command line, parent process,
  service and task details, share access, ticket encryption, technique, source file.
- Rules: log cleared, password spray, failure bursts, RDP pre-auth floods, RDP from public
  addresses, local-account NTLM network logons, NewCredentials / pass-the-hash, privileged group
  changes (new-account escalation is Critical), Kerberoasting, DC ticket fan-out, lockouts,
  privileged remote logons, every remote-exec session. MITRE ids and counts on every finding.
- Triage `timeline.csv` subset, CIDR / prefix / exact IP filters, live-channel access checks,
  Velociraptor collection-name host inference, WPF Remote Sessions tab and event detail pane
  with the original XML, import cancel, LICENSE, CI workflow.

### Fixed
- Events were routed by event ID alone (System Kernel-Boot 25 became an RDP reconnect).
- Findings were duplicated in the case database on every import; re-importing duplicated events.
- After-hours rule used UTC and fired once per event (incl. 4672 / 1149).
- RDP 1149 (NLA) was counted as a successful logon.
- SYSTEM, machine, DWM and UMFD accounts inflated "privileged" counts.
- `DOMAIN\user`, `user@realm` and bare names did not join; FQDN and NetBIOS hosts did not join.
- 4648 lost the acting account; Security "-" placeholders shadowed real values.
- CSV export was open to spreadsheet formula injection; timestamps carried no time zone.
- A corrupt record could loop the reader forever; unnamed `<Data>` fields were dropped.
- IP filter was a substring match ("10.0.0.1" matched "10.0.0.15").
- WPF date filters were interpreted as local time against UTC data; quick-triage cases were
  written silently under `%TEMP%`; grids refreshed row by row.
- Localised console addresses ("本機") were treated as RDP sources.
