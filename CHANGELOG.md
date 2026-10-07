# Changelog

## 0.4.4 — 2026-10-07

### Added
- **`ipnames.csv`**: every IP address → name pair the logs record, with counts, first / last seen
  and event ids.
  - `client-reported`: the workstation name a client supplied at logon (4624 / 4625
    `WorkstationName`, 4778 / 4779 `ClientName`). This includes the NTLM network logon that
    precedes each RDP connection under NLA. The logging host's own name, "Unknown", addresses and
    loopback sources (127.0.0.2 RDP tunnels included) are left out.
  - `self`: the host's own address, from a 4624 type 3 logon whose client named itself as this host,
    or a 4648 whose target is this host.
- **Known hosts → Learned from these logs** reads `ipnames.csv`, so names now come from the full event
  set (network logons are not in the Timeline's triage subset). Results from older engines fall back
  to the sessions as before.
- **The scanned host's own address is added to Known hosts automatically** after every Process, and
  when results without a `knownhosts.csv` are loaded, so a row you delete stays deleted until the next
  Process. An address that is already labelled, or that also reported another client name, is left
  for the dialog. The log says when the logs show no own address.

### Changed
- The results table fills the window: with the tabs scrolled to the top, the table reaches the bottom
  of the window instead of stopping at 58 % of its height. It is recalculated on resize and with the
  font-size buttons, and a row's detail card scrolls into view when it opens below the window.

## 0.4.3 — 2026-10-07

### Fixed
- **Wrong client names for inbound RDP.** Under NLA, the 4624 type 10 `WorkstationName` is the RDP
  server's own name, and the engine used it as the session's `SourceHost`, so every client looked like
  the server itself. Sessions now take the 4778 / 4779 `ClientName` first and never use the session
  host's own name (left empty when the logs name no client).
- **Known hosts → Learned from these logs** offered those self-names (six client IPs all "learned" as
  the server). It also listed an address once per name, so `add all` silently kept whichever came last,
  and it offered loopback addresses. Now each address appears once with how often and when it was seen.
  An address seen with different names (DHCP reuse, a spoofed or renamed client) is shown as a conflict
  to label by hand. A name equal to the logging host is dropped, which also cleans results from older
  engines. A suggestion that differs from your own label is marked, and `add all` leaves out
  conflicts and changes to your labels.

## 0.4.2 — 2026-10-07

### Added
- **More remote access products** for the "Remote access software installed / executed" rule (about 60
  now): ToDesk, HopToDesk, Sunlogin (Oray), AweSun, UltraViewer, AnyViewer, ISL Online, DWService,
  Parsec, Iperius Remote, Getscreen.me, FleetDeck, Remotely, NoMachine, GoToMyPC, LiteManager, TigerVNC,
  pcAnywhere, Mikogo, ShowMyPC, Jump Desktop, RemotePC, Bomgar, Netop and SuperOps. As before, a product is
  recognised by its service name or binary path in 7045 / 4697 service installs and 4688 / Sysmon 1
  process starts. Renamed binaries and portable tools that install no service are missed when process
  auditing is off.
- **App icon.** A magnifier over an account, in the app's own colours: `LoginActivityTriage.ico`
  (16-256 px, with a simplified drawing at 16 and 24 px). The engine exe carries it, the manual uses it
  as its browser-tab icon, and **Help → Create desktop shortcut** makes a shortcut to this copy of the
  app with it (the shortcut starts `mshta.exe` directly, so it works where `.hta` files are associated
  with something else). Releases attach the `.ico` and the bundle includes it.
- The running HTA window keeps the standard mshta icon: mshta ignores `HTA:APPLICATION ICON=` in the
  IE=edge document mode the app needs, and setting the icon at runtime would mean a hidden helper
  process running for as long as the window is open.

### Fixed
- **Findings "missing" behind the date filter.** The overview tiles and the "Findings by rule" chart
  count every row, but the tables apply the from / to dates. After a run without an engine window, a
  date typed later hid older findings with no hint: a chart bar said 1 and its table showed 0. The row
  count now says how many matching rows the dates hide (*+N outside the dates*), an empty table says
  so too, and **show all dates** clears the window.

## 0.4.1 — 2026-10-07

### Fixed
- **Update engine refused every download in 0.4.0** with "SHA-256 mismatch: the release lists , the
  download is …". GitHub serves release assets as `application/octet-stream`, for which Windows
  PowerShell 5.1 returns the response as a byte array, not text, so the checksum line for the engine was
  never found and the empty value was reported as a mismatch. The engine itself was intact. The checksum
  list is now saved to a file and read as text, the asset name is compared exactly rather than as a
  pattern, and "no entry in the checksum list" is reported separately from a real mismatch.
- The 0.4.0 self-update had the same lookup; there the missing line fell through to "no checksum file",
  so an update from 0.4.0 installs without verification (the status line says so). From 0.4.1 both
  paths share one checked function, and a checksum list without an entry for the file refuses it.
- A failed download or self-update now shows the actual reason on the status line.

## 0.4.0 — 2026-10-07

The feature items of the 7 October review.

### Added
- **Evidence hashes.** `files.csv` records the **SHA-256 and size of every source log** as it was read
  (`Sha256`, `SizeBytes`; `summary.json` says `fileHashes: SHA-256`), so the results carry the
  chain-of-custody record of exactly which bytes were analysed. `--no-hash` skips it. The HTA's Import
  log explains each column on hover, and the temporary copy *Open in Event Viewer* makes of a long-path
  log is now checked against the recorded hash (certutil) and refused if it differs.
- **Public-source rules beyond RDP** (the previous rule needed a 4624 type 10 / 12 or LSM 21):
  *Network logon from external address* (High: a successful type 3 / 8 logon from a routable address -
  SMB, WinRM, RPC reachable from the internet, and the credentials worked); *RDP authentication from
  external address* (High: RCM 1149 from a public address with no session logon in the logs); *RDP
  reachable from the internet* (Medium, one finding per host: RdpCoreTS 131 / 140 connections from
  public addresses, with the addresses listed, so a scanned listener does not flood the list).
- **Group removals and renames.** 4729 / 4733 / 4757 (member removed) and 4781 (account renamed) are
  imported. *Privileged group membership added then removed* (High) catches the add-use-remove cleanup
  pattern within a day; a removal with no recent add is *Member removed from privileged group*
  (Medium). A renamed account is named by its current name everywhere (the SID resolver follows the
  rename), the old name stays in Details, and the Users pivot's `GroupChanges` counts removals too.
- **More 4648 SPN classes.** Explicit credentials for a `cifs/` SPN are an outbound **SMB** session
  (file / admin shares on another host, finding *Outbound SMB with explicit credentials from this
  host*, Low) and `RPCSS/` an outbound WMI / DCOM hand-off, alongside the existing `TERMSRV/`,
  `HTTP/` and `WSMAN/`.
- **Business hours across midnight**: `--hours 22-6` means a shift from 22:00 to 06:00; after hours is
  the daytime.
- **Release checksums.** CI attaches `SHA256SUMS.txt` to every release; **Update** and **Update
  engine** download to a temporary file, verify it against that list and discard a mismatch. The
  status line says whether the download was verified.
- **Offline mode**: `/offline` on the command line or `LAT_OFFLINE=1` in the environment keeps the HTA
  off the network (no GitHub update check, no downloads); the app pill says "offline".
- Tests: 143 (`FeatureTests040`).

## 0.3.3 — 2026-10-07

Fixes from the 4 and 7 October code reviews (`review-artifacts-2026-10-07` fixtures reproduce the engine items).

### Fixed
- **HTA: the Event Viewer copy cache is cleaned without following links.** The start-up cleanup of
  `%TEMP%\LoginActivityTriage-evx` deleted every subfolder recursively through FileSystemObject, which
  follows a junction or symbolic link: a link planted there would have exposed its target to the
  delete. Cleanup now removes only this app's own entries (a uid-named folder holding plain files),
  never deletes through a reparse point at the root, folder or file level, and reports what it left.
- **HTA: input text is validated before it is quoted into the engine command.** A path over 259
  characters that neither the plain nor the `\\?\` check can see is still passed on for the engine to
  judge, but any input, output folder or time-zone value containing a double quote or a control
  character is now refused (`pathSafe`) instead of being written into the generated `.bat` line, where a
  quote could end the argument. The same check guards the command-line hand-off and the Event Viewer copy.
- **HTA: an already-extended `\\?\` or `\\?\UNC\` source path works everywhere.** `lpForm` is now
  idempotent, so results produced from a `\\?\` input open in Event Viewer; the `\\.\` device form is
  reported as unsupported instead of as "no temporary folder".
- **HTA: a run counts only with a summary.json that this run published.** The run must produce a
  summary generated after it started (5 s tolerance, same clock) and different from the one in the folder
  before it. Previously a summary up to two minutes older than the start passed when the exit marker was
  missing (console closed or killed).
- **HTA: a results folder at a path over 259 characters is refused with the cure** ("copy it to a shorter
  path") on the command line and in *Load results…*, instead of being handed to the engine as EVTX
  input and failing with "No .evtx files were found".
- **Engine: the "New account added to privileged group" rule matched a creation on another host by bare
  name.** Once 0.3.2 named local group members, two different local accounts with the same name on two
  hosts (`backup` created on HOSTA, a different `backup` added to Administrators on HOSTB) produced a
  false Critical. When both events carry a SID, only the SIDs decide; the name is used only when a SID is
  missing, and then domain-aware.
- **Engine: the SID resolver no longer learns names from RunAs / JEA remoting records.** A PowerShell
  4103 on such an endpoint names the connected user but is logged under the endpoint's RunAs account, so
  the resolver paired that account's SID with the connected user's name and applied it to events the
  RunAs account logged (a 7045 install). Names are now learned only from Security events, which pair the
  account's own SID with its name, and the 4103 keeps the connected user as its subject with the process
  account noted in Details and no SID.
- **Engine: a service install alone is no longer a High PsExec finding.** A `PSEXESVC` install with no
  network logon, no pipe and no source address (PsExec run on the box itself, or an unattributed run) is
  a Low-confidence session, so its finding is Medium and the evidence says why.
- HTA `runinfo.json` lists the files the run actually published (it omitted `timeline.csv`,
  `remotehosts.csv` and the HTML reports); the two "NTLM V1 / V2" tooltips that could never show were
  folded into the NTLM tip (the LM package is in Details); the Remote sessions table shows LogonType and
  AuthPackage, so the 0.3.2 note about value tooltips there is true.

### Changed
- **Update engine** downloads the engine of this app's own release (`v<app version>`) and falls back to
  the latest release only when that tag has no engine asset, so the pair stays in step. An engine newer
  than the app is now flagged too.
- Tests: 133 (three new in `SidResolutionTests`).

## 0.3.2 — 2026-10-04

### Fixed
- **Group-membership events named a local account by its SID** even when the logs name it.
  4728 / 4732 / 4756 for a local account log `MemberName` "-" and only the `MemberSid`, so the
  event, the Users row and the "New account added to privileged group" finding showed
  `S-1-5-21-...-1003` although the account's 4720 creation and its 4624 logons pair that SID with
  its name. The SID resolver now names such members from those events (with the account's own
  domain, not the group's), and the finding keeps the SID beside the name:
  `svc_report (S-1-5-21-...-1003) added to Administrators`. A member no event names stays listed by
  its SID.

### Added
- **Sid in the Users pivot**: `users.csv` has a `Sid` column (the account's SIDs as logged, most
  frequent first; the NULL SID of failed logons is left out). The HTA shows it on the Users detail
  card, includes it in search and *Export view → CSV*, and keeps it out of the table.
- **Engine older than app**: the HTA flags an engine from an older release (red engine pill,
  "older than app") and offers **Update engine** (latest GitHub release). The self-update replaces
  only the `.hta`, so an old engine could otherwise go unnoticed and silently miss a release's
  engine fixes.
- **Tooltips**: every Timeline column heading explains what the column holds (e.g. SourceIp is the
  remote client - for an RDP logon the machine the connection came from - and the Workstation of a
  type 10 logon is the server's own name). LogonType values (0-13) and AuthPackage values
  (Kerberos, NTLM, Negotiate, MSV1_0, NTLM V1/V2, CloudAP...) explain themselves on hover, in the
  Timeline and the Remote sessions table.

## 0.3.1 — 2026-10-04

### Fixed
- **Open in Event Viewer for a source log past MAX_PATH** did not work in 0.3.0. Event Viewer
  refuses a saved log at a path of 260+ characters in any form: for the plain path and for its
  `\\?\` form alike it reports "The following file does not exist", although the event log API
  underneath reads the `\\?\` form. Such a log is now copied (read once from the evidence, never
  written) to `%TEMP%\LoginActivityTriage-evx` and Event Viewer opens the copy, still filtered to
  the one record. The status line says when a copy is used; the copies are removed at the next
  start (the Event Log service keeps a log it opened locked for a while after Event Viewer closes).

### Changed
- CI: the workflow actions moved to their Node 24 majors (checkout v7, setup-dotnet v6,
  upload-artifact v7, action-gh-release v3).

## 0.3.0 — 2026-10-04

### Fixed
- **Evidence paths past MAX_PATH** (260 characters), routine in Velociraptor / KAPE trees
  (`...\Collection-HOST-...\uploads\auto\C%3A\Windows\System32\winevt\Logs\...`):
  - Engine: the Windows event log API failed every such `.evtx` with status 3 ("The system cannot
    find the path specified"), so the run ended "None of the input logs could be read" (exit 4).
    The reader now opens a long path through its `\\?\` extended-length form; shorter paths are
    passed unchanged.
  - HTA: inside mshta, FileSystemObject reports a 260+ character path as missing, so a long folder
    handed over by the DFIR Artifact Finder (or typed in) was refused ("CLI input not found",
    "Directory not found"). The input checks now re-check a long path through `\\?\` (the HTA
    wrapper family's long-path fix); a long path that cannot be verified at all is passed on with a
    note, and the engine reports a real miss.
  - HTA: *Open in Event Viewer* works for a long source log (Event Viewer is handed the `\\?\` form)
    instead of reporting "Source log not found".
  - HTA: a rejected command-line input now stays on screen as "CLI input not found" and is logged;
    the start-up prompt used to overwrite it, so the hand-off failed silently.

## 0.2.2 — 2026-10-04

### Added
- **Open an event in Event Viewer**: on the HTA Timeline, clicking an EventId (or *Open in Event
  Viewer* on the detail card) opens the source `.evtx` in Windows Event Viewer already filtered to
  that one record (`eventvwr /l:<file> /f:"*[System[(EventRecordID=n)]]"`); live-log results open
  the live channel with `/c:`. Launched with ShellExecute so `%` in Velociraptor paths is not
  expanded; the app reports when the source file is no longer at its processed path.

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
