using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Storage;

/// <summary>A persisted NormalizedEvents column: SQL type plus read / write mapping.</summary>
internal sealed record EventColumn(
    string Name,
    string SqlType,
    Func<NormalizedEvent, object?> Get,
    Action<NormalizedEvent, object?>? Set);

/// <summary>
/// SQLite schema for a triage case database. Raw event XML is preserved in a dedicated
/// RawEvents table so the original record is always recoverable, while NormalizedEvents holds
/// the flat, query-optimised projection used by the UI.
///
/// <see cref="EventColumns"/> is the single source of truth for the event table: CREATE,
/// migration of older case files (ALTER TABLE ADD COLUMN), INSERT and SELECT all derive from it.
/// </summary>
internal static class CaseSchema
{
    private static string? S(object? v) => v is null or DBNull ? null : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture);
    private static long? L(object? v) => v is null or DBNull ? null : Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture);
    private static int? I(object? v) => v is null or DBNull ? null : Convert.ToInt32(v, System.Globalization.CultureInfo.InvariantCulture);
    private static bool B(object? v) => L(v) is { } x && x != 0;
    private static object Db(object? v) => v ?? DBNull.Value;
    private static object Db(bool? v) => v is null ? DBNull.Value : (v.Value ? 1 : 0);

    public static readonly IReadOnlyList<EventColumn> EventColumns = new EventColumn[]
    {
        new("Hostname", "TEXT", e => Db(e.Hostname), (e, v) => e.Hostname = S(v)),
        new("LogSource", "TEXT", e => Db(e.LogSource), (e, v) => e.LogSource = S(v)),
        new("SourceFile", "TEXT", e => Db(e.SourceFile), (e, v) => e.SourceFile = S(v)),
        new("EventId", "INTEGER", e => e.EventId, (e, v) => e.EventId = I(v) ?? 0),
        new("Provider", "TEXT", e => Db(e.Provider), (e, v) => e.Provider = S(v)),
        new("RecordId", "INTEGER", e => Db(e.RecordId), (e, v) => e.RecordId = L(v)),
        new("Channel", "TEXT", e => Db(e.Channel), (e, v) => e.Channel = S(v)),
        new("EventType", "TEXT", e => Db(e.EventType), (e, v) => e.EventType = S(v) ?? string.Empty),
        new("TargetUserName", "TEXT", e => Db(e.TargetUserName), (e, v) => e.TargetUserName = S(v)),
        new("TargetDomain", "TEXT", e => Db(e.TargetDomain), (e, v) => e.TargetDomain = S(v)),
        new("Sid", "TEXT", e => Db(e.Sid), (e, v) => e.Sid = S(v)),
        new("SubjectUserName", "TEXT", e => Db(e.SubjectUserName), (e, v) => e.SubjectUserName = S(v)),
        new("SubjectDomain", "TEXT", e => Db(e.SubjectDomain), (e, v) => e.SubjectDomain = S(v)),
        new("SubjectLogonId", "TEXT", e => Db(e.SubjectLogonId), (e, v) => e.SubjectLogonId = S(v)),
        new("LogonId", "TEXT", e => Db(e.LogonId), (e, v) => e.LogonId = S(v)),
        new("LinkedLogonId", "TEXT", e => Db(e.LinkedLogonId), (e, v) => e.LinkedLogonId = S(v)),
        new("SessionId", "TEXT", e => Db(e.SessionId), (e, v) => e.SessionId = S(v)),
        new("SourceIp", "TEXT", e => Db(e.SourceIp), (e, v) => e.SourceIp = S(v)),
        new("SourcePort", "TEXT", e => Db(e.SourcePort), (e, v) => e.SourcePort = S(v)),
        new("WorkstationName", "TEXT", e => Db(e.WorkstationName), (e, v) => e.WorkstationName = S(v)),
        new("LogonType", "INTEGER", e => Db(e.LogonType), (e, v) => e.LogonType = I(v)),
        new("LogonTypeDescription", "TEXT", e => Db(e.LogonTypeDescription), (e, v) => e.LogonTypeDescription = S(v)),
        new("AuthenticationPackage", "TEXT", e => Db(e.AuthenticationPackage), (e, v) => e.AuthenticationPackage = S(v)),
        new("LogonProcess", "TEXT", e => Db(e.LogonProcess), (e, v) => e.LogonProcess = S(v)),
        new("ElevatedToken", "INTEGER", e => Db(e.ElevatedToken), (e, v) => e.ElevatedToken = L(v) is { } x ? x != 0 : null),
        new("ImpersonationLevel", "TEXT", e => Db(e.ImpersonationLevel), (e, v) => e.ImpersonationLevel = S(v)),
        new("PrivilegeList", "TEXT", e => Db(e.PrivilegeList), (e, v) => e.PrivilegeList = S(v)),
        new("ProcessName", "TEXT", e => Db(e.ProcessName), (e, v) => e.ProcessName = S(v)),
        new("ProcessId", "TEXT", e => Db(e.ProcessId), (e, v) => e.ProcessId = S(v)),
        new("ParentProcessName", "TEXT", e => Db(e.ParentProcessName), (e, v) => e.ParentProcessName = S(v)),
        new("CommandLine", "TEXT", e => Db(e.CommandLine), (e, v) => e.CommandLine = S(v)),
        new("TargetServer", "TEXT", e => Db(e.TargetServer), (e, v) => e.TargetServer = S(v)),
        new("ServiceName", "TEXT", e => Db(e.ServiceName), (e, v) => e.ServiceName = S(v)),
        new("ServiceFileName", "TEXT", e => Db(e.ServiceFileName), (e, v) => e.ServiceFileName = S(v)),
        new("ServiceType", "TEXT", e => Db(e.ServiceType), (e, v) => e.ServiceType = S(v)),
        new("ServiceStartType", "TEXT", e => Db(e.ServiceStartType), (e, v) => e.ServiceStartType = S(v)),
        new("ServiceAccount", "TEXT", e => Db(e.ServiceAccount), (e, v) => e.ServiceAccount = S(v)),
        new("TaskName", "TEXT", e => Db(e.TaskName), (e, v) => e.TaskName = S(v)),
        new("ShareName", "TEXT", e => Db(e.ShareName), (e, v) => e.ShareName = S(v)),
        new("RelativeTargetName", "TEXT", e => Db(e.RelativeTargetName), (e, v) => e.RelativeTargetName = S(v)),
        new("AccessMask", "TEXT", e => Db(e.AccessMask), (e, v) => e.AccessMask = S(v)),
        new("GroupName", "TEXT", e => Db(e.GroupName), (e, v) => e.GroupName = S(v)),
        new("TicketEncryptionType", "TEXT", e => Db(e.TicketEncryptionType), (e, v) => e.TicketEncryptionType = S(v)),
        new("Status", "TEXT", e => Db(e.Status), (e, v) => e.Status = S(v)),
        new("SubStatus", "TEXT", e => Db(e.SubStatus), (e, v) => e.SubStatus = S(v)),
        new("FailureReason", "TEXT", e => Db(e.FailureReason), (e, v) => e.FailureReason = S(v)),
        new("Details", "TEXT", e => Db(e.Details), (e, v) => e.Details = S(v)),
        new("UtcOffsetMinutes", "INTEGER", e => Db(e.UtcOffsetMinutes), (e, v) => e.UtcOffsetMinutes = I(v)),
        new("Technique", "TEXT", e => Db(e.Technique), (e, v) => e.Technique = S(v)),
        new("TechniqueDetail", "TEXT", e => Db(e.TechniqueDetail), (e, v) => e.TechniqueDetail = S(v)),
        new("Activity", "TEXT", e => Db(e.Activity), (e, v) => e.Activity = S(v)),
        new("IsOutbound", "INTEGER NOT NULL DEFAULT 0", e => e.IsOutbound ? 1 : 0, (e, v) => e.IsOutbound = B(v)),
        new("IsSuccess", "INTEGER NOT NULL DEFAULT 0", e => e.IsSuccess ? 1 : 0, (e, v) => e.IsSuccess = B(v)),
        new("IsFailure", "INTEGER NOT NULL DEFAULT 0", e => e.IsFailure ? 1 : 0, (e, v) => e.IsFailure = B(v)),
        // Derived flags stored for SQL filtering only.
        new("IsMachineAccount", "INTEGER NOT NULL DEFAULT 0", e => e.IsMachineAccount ? 1 : 0, null),
        new("IsPrivileged", "INTEGER NOT NULL DEFAULT 0", e => e.IsPrivileged ? 1 : 0, null),
        new("IsRdp", "INTEGER NOT NULL DEFAULT 0", e => e.IsRdp ? 1 : 0, null),
        new("DedupeKey", "TEXT", e => e.DedupeKey, null),
    };

    public static string CreateSql => $@"
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
    Id            INTEGER PRIMARY KEY AUTOINCREMENT,
    CaseId        INTEGER NOT NULL REFERENCES Cases(Id),
    TimestampUtc  TEXT NOT NULL,
    UnixMs        INTEGER NOT NULL,
    {string.Join(",\n    ", EventColumns.Select(c => $"{c.Name} {c.SqlType}"))}
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
    Reasoning       TEXT,
    Mitre           TEXT,
    Count           INTEGER NOT NULL DEFAULT 1,
    SessionRef      INTEGER
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
";

    /// <summary>Indexes are created after migration so they can reference newly added columns.</summary>
    public const string IndexSql = @"
CREATE INDEX IF NOT EXISTS IX_Events_Case      ON NormalizedEvents(CaseId);
CREATE INDEX IF NOT EXISTS IX_Events_Time      ON NormalizedEvents(UnixMs);
CREATE INDEX IF NOT EXISTS IX_Events_EventId   ON NormalizedEvents(EventId);
CREATE INDEX IF NOT EXISTS IX_Events_User      ON NormalizedEvents(TargetUserName);
CREATE INDEX IF NOT EXISTS IX_Events_Host      ON NormalizedEvents(Hostname);
CREATE INDEX IF NOT EXISTS IX_Events_SourceIp  ON NormalizedEvents(SourceIp);
CREATE INDEX IF NOT EXISTS IX_Events_LogonId   ON NormalizedEvents(LogonId);
CREATE UNIQUE INDEX IF NOT EXISTS UX_Events_Dedupe ON NormalizedEvents(CaseId, DedupeKey);
";
}
