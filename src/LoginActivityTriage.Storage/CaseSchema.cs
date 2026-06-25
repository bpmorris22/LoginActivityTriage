namespace LoginActivityTriage.Storage;

/// <summary>
/// SQLite schema for a triage case database. Raw event XML is preserved in a
/// dedicated RawEvents table so the original record is always recoverable, while
/// NormalizedEvents holds the flat, query-optimised projection used by the UI.
/// </summary>
internal static class CaseSchema
{
    public const string CreateSql = @"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Cases (
    Id           INTEGER PRIMARY KEY AUTOINCREMENT,
    Name         TEXT NOT NULL,
    Analyst      TEXT,
    Description  TEXT,
    CreatedUtc   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ImportedFiles (
    Id               INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId           INTEGER NOT NULL REFERENCES Cases(Id),
    FilePath         TEXT NOT NULL,
    Hostname         TEXT,
    LogSource        TEXT,
    RecordsRead      INTEGER NOT NULL DEFAULT 0,
    EventsNormalised INTEGER NOT NULL DEFAULT 0,
    RecordsSkipped   INTEGER NOT NULL DEFAULT 0,
    Failed           INTEGER NOT NULL DEFAULT 0,
    Error            TEXT,
    ImportedUtc      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS NormalizedEvents (
    Id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId                INTEGER NOT NULL REFERENCES Cases(Id),
    TimestampUtc          TEXT NOT NULL,
    UnixMs                INTEGER NOT NULL,
    Hostname              TEXT,
    LogSource             TEXT,
    EventId               INTEGER NOT NULL,
    Provider              TEXT,
    RecordId              INTEGER,
    Channel               TEXT,
    EventType             TEXT,
    TargetUserName        TEXT,
    TargetDomain          TEXT,
    Sid                   TEXT,
    SourceIp              TEXT,
    SourcePort            TEXT,
    WorkstationName       TEXT,
    LogonType             INTEGER,
    LogonTypeDescription  TEXT,
    AuthenticationPackage TEXT,
    LogonProcess          TEXT,
    ElevatedToken         INTEGER,
    ImpersonationLevel    TEXT,
    ProcessName           TEXT,
    ProcessId             TEXT,
    TargetServer          TEXT,
    ServiceName           TEXT,
    GroupName             TEXT,
    Status                TEXT,
    SubStatus             TEXT,
    FailureReason         TEXT,
    IsSuccess             INTEGER NOT NULL DEFAULT 0,
    IsFailure             INTEGER NOT NULL DEFAULT 0,
    IsMachineAccount      INTEGER NOT NULL DEFAULT 0,
    IsPrivileged          INTEGER NOT NULL DEFAULT 0,
    IsRdp                 INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS RawEvents (
    EventRowId INTEGER PRIMARY KEY REFERENCES NormalizedEvents(Id) ON DELETE CASCADE,
    RawXml     TEXT
);

CREATE TABLE IF NOT EXISTS Findings (
    Id              INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId          INTEGER NOT NULL REFERENCES Cases(Id),
    Severity        INTEGER NOT NULL,
    RuleName        TEXT NOT NULL,
    Description     TEXT,
    TimestampUtc    TEXT,
    User            TEXT,
    SourceIp        TEXT,
    Host            TEXT,
    RelatedEventIds TEXT,
    Reasoning       TEXT
);

CREATE TABLE IF NOT EXISTS Bookmarks (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId      INTEGER NOT NULL REFERENCES Cases(Id),
    EventRowId  INTEGER NOT NULL REFERENCES NormalizedEvents(Id),
    CreatedUtc  TEXT NOT NULL,
    Label       TEXT
);

CREATE TABLE IF NOT EXISTS Notes (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId      INTEGER NOT NULL REFERENCES Cases(Id),
    EventRowId  INTEGER REFERENCES NormalizedEvents(Id),
    CreatedUtc  TEXT NOT NULL,
    Text        TEXT NOT NULL
);

-- Investigator IOC lists, one row per case (free-form text, newline separated).
CREATE TABLE IF NOT EXISTS Iocs (
    CaseId     INTEGER PRIMARY KEY REFERENCES Cases(Id) ON DELETE CASCADE,
    Hosts      TEXT,
    Ips        TEXT,
    Users      TEXT,
    UpdatedUtc TEXT
);

-- Aggregate pivot tables (optional cache; pivots are also computed on the fly).
CREATE TABLE IF NOT EXISTS Users     (CaseId INTEGER, Name TEXT);
CREATE TABLE IF NOT EXISTS Hosts     (CaseId INTEGER, Name TEXT);
CREATE TABLE IF NOT EXISTS SourceIPs (CaseId INTEGER, Address TEXT);

CREATE INDEX IF NOT EXISTS IX_Events_Case      ON NormalizedEvents(CaseId);
CREATE INDEX IF NOT EXISTS IX_Events_Time      ON NormalizedEvents(UnixMs);
CREATE INDEX IF NOT EXISTS IX_Events_EventId   ON NormalizedEvents(EventId);
CREATE INDEX IF NOT EXISTS IX_Events_User      ON NormalizedEvents(TargetUserName);
CREATE INDEX IF NOT EXISTS IX_Events_Host      ON NormalizedEvents(Hostname);
CREATE INDEX IF NOT EXISTS IX_Events_SourceIp  ON NormalizedEvents(SourceIp);
";
}
