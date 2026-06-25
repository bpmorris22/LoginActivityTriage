# Login Activity Triage GUI

A focused, investigator-first Windows desktop tool for **rapid DFIR triage of Windows
authentication activity** from offline EVTX files. It is *not* a generic event viewer —
it normalises logon-relevant events into a single timeline and helps answer:

> Who logged in? From where? To which host? Using what logon type? Was it privileged?
> Was it RDP / interactive / network / service? What happened before and after?

Offline-first. No cloud, no telemetry, no internet requirement.

---

## Status: MVP

This repository implements the **MVP milestone** end-to-end, with several
post-MVP capabilities already in place. See [Feature status](#feature-status).

The MVP acceptance criteria are met:

- Select a folder of EVTX files and import `Security.evtx` recursively.
- Extract and normalise **4624, 4625, 4648, 4672** (plus RDP/TS events as a bonus).
- Display a useful, sortable, filterable **Logon Timeline**.
- Filter by user, source IP, host, Event ID, logon type and time range.
- Right-click any row → **Show Logon Story** (±15 / ±30 / ±60 min).
- Export the current view to **CSV** (and HTML).
- Missing fields and malformed XML are handled without crashing.

---

## Technology

| Area | Choice |
|---|---|
| Language / runtime | C# / .NET 8 |
| UI | WPF (MVVM) |
| EVTX parsing | `System.Diagnostics.Eventing.Reader` |
| Case storage | SQLite (`Microsoft.Data.Sqlite`) |
| Export | Native CSV + self-contained HTML |
| Tests | xUnit |

---

## Solution layout

```
LoginActivityTriage/
  LoginActivityTriage.sln
  src/
    LoginActivityTriage.Core/        Models, enums, logon-type & event catalogs (no deps)
    LoginActivityTriage.Parsing/     EVTX reader + event normalisers (testable, XML-driven)
    LoginActivityTriage.Storage/     SQLite schema + case repository
    LoginActivityTriage.Analytics/   Rule-based suspicious-sequence detection
    LoginActivityTriage.Export/      CSV + HTML exporters
    LoginActivityTriage.App/         WPF MVVM application (entry point)
  tests/
    LoginActivityTriage.Tests/       Unit tests with sample event XML
```

Parsing and UI are kept strictly separate: the normaliser operates on an event's
XML string (`EventXmlData` + `*Normalizer`), so all normalisation logic is unit-tested
without touching the Windows EVTX APIs.

---

## Build & run

### Prerequisites

- Windows 10 / 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

Verify the SDK:

```powershell
dotnet --list-sdks   # expect an 8.0.x entry
```

### Build everything

```powershell
cd LoginActivityTriage
dotnet build LoginActivityTriage.sln -c Release
```

### Run the app

```powershell
dotnet run --project src\LoginActivityTriage.App -c Release
```

Or launch the built executable directly:

```
src\LoginActivityTriage.App\bin\Release\net8.0-windows\LoginActivityTriage.exe
```

### Run the tests

```powershell
dotnet test
```

---

## Usage

1. **Create a case** — *New Case* prompts for a `.latdb` file (the SQLite case
   database). Alternatively just hit *Import EVTX Folder…* and a quick-triage
   case is created automatically under `%TEMP%`.
2. **Import** — choose a folder; every `*.evtx` beneath it is discovered
   recursively. Progress is shown in the status bar. Hostnames are inferred from
   the event XML (`Computer`) or, failing that, the containing folder name
   (common in Velociraptor/KAPE-style collections, e.g. `…\HOST01\Security.evtx`).
   Parse errors and skipped records are listed under the **Import Log** tab.
3. **Triage** on the tabs:
   - **Dashboard** — summary cards and top-N lists (users, source IPs, hosts,
     privileged users, RDP source IPs).
   - **Logon Timeline** — the normalised grid with full filters and one-click
     *Quick* filters (RDP, Failures, Privileged, Explicit creds, NTLM, Kerberos
     failures, Service installed, Account created, Logon Type 3 / 10, exclude
     machine accounts).
   - **Suspicious Sequences** — rule-based findings with severity and reasoning.
   - **Import Log** — errors and skipped files.
4. **Logon Story** — right-click any timeline row → *Show Logon Story*. A window
   opens showing every event that shares the same user, source IP **or** host
   within ±N minutes of the selected event (window size is set in the toolbar).
5. **Export** — *Export CSV* / *Export HTML* write the **current filtered view**.

### Logon type reference

| Type | Meaning | | Type | Meaning |
|---|---|---|---|---|
| 2 | Interactive | | 8 | NetworkCleartext |
| 3 | Network | | 9 | NewCredentials |
| 4 | Batch | | 10 | RemoteInteractive / RDP |
| 5 | Service | | 11 | CachedInteractive |
| 7 | Unlock | | | |

---

## Normalised fields

Each event is flattened to a single row. Depending on the Event ID the following
are populated where present: Timestamp, Hostname, Log source, Event ID, Provider,
Record ID, Channel, Event type, User, Domain, SID, Source IP, Source port,
Workstation, Logon type (+ description), Authentication package, Logon process,
Elevated token, Impersonation level, Process name/ID, Target server, Service name,
Group name, Status, SubStatus, Failure reason, and the original **Raw XML**.

`4625` failure reasons are decoded from the NTSTATUS `SubStatus` (falling back to
`Status`), e.g. `0xC000006A → Bad password`, `0xC0000234 → Account locked out`.

---

## SQLite schema

A case database contains: `Cases`, `ImportedFiles`, `NormalizedEvents`,
`RawEvents` (original XML, 1:1 with normalised rows), `Findings`, `Bookmarks`,
`Notes`, and `Users` / `Hosts` / `SourceIPs` aggregate tables. Timestamps are
stored both as ISO-8601 (`TimestampUtc`) and epoch-milliseconds (`UnixMs`, indexed
for fast range queries).

---

## Suspicious-sequence rules (current)

1. Failed logons followed by a successful logon from the same source IP.
2. One source IP authenticating to many hosts within 30 minutes (lateral movement).
3. One user authenticating to many hosts within 30 minutes.
4. Successful logon outside business hours (07:00–19:00).

Each finding carries Severity, Rule name, Description, Timestamp, User, Source IP,
Host, Related Event IDs and Reasoning.

---

## Feature status

**Implemented (MVP + extras):** case creation, recursive EVTX import with progress
and error capture, Security normalisation (4624/4625/4648/4672), Terminal-Services
normalisation (1149/21/22/24/25/39/40), SQLite case cache with raw XML, Dashboard,
Logon Timeline with full filters + quick filters, **RDP Activity**, **Failed Logons**
and **Admin Usage** tabs, **Source IP / User / Host pivot** tabs (with a heuristic
suspicion score), Suspicious Sequences, Logon Story, CSV/HTML export, virtualised
grids, unit tests.

**Planned (designed for, not yet built):** normalisation of the remaining Security /
System event IDs (account & group changes 4720–4756, Kerberos/NTLM 4768–4776, service
install 7045) and the detection rules that depend on them (service-after-network-logon,
new-account-then-privileged-group, NTLM-from-unusual-source), plus bookmarks/notes UI
and a full case-summary report. The architecture (additive `IEventNormalizer`s,
additive analytics rules, a filter model shared by SQL and in-memory paths) is built
so these extend cleanly.

Note: the pivot grids include the columns derivable from the events parsed today;
the spec's *group-changes* (User pivot) and *service-installs* (Host pivot) columns
arrive once those event IDs are normalised.

---

## Design principles

- **Investigator workflow over feature completeness.**
- **Never crash on bad data** — malformed XML and missing fields are tolerated at
  every layer; per-record and per-file failures are isolated and reported.
- **Parsing logic is separate from UI** and fully unit-testable.
- **Offline, local, no telemetry.**
