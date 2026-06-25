using System.Globalization;
using System.Text;
using LoginActivityTriage.Core.Models;
using Microsoft.Data.Sqlite;

namespace LoginActivityTriage.Storage;

/// <summary>
/// Repository over a single case's SQLite database. Owns one connection for the
/// lifetime of the open case. All writes for an import go through a single
/// transaction for throughput.
/// </summary>
public sealed class CaseStore : IDisposable
{
    private readonly SqliteConnection _connection;

    public string DatabasePath { get; }
    public long CaseId { get; private set; }

    private CaseStore(SqliteConnection connection, string path)
    {
        _connection = connection;
        DatabasePath = path;
    }

    /// <summary>Opens (creating if needed) a case database and ensures the schema exists.</summary>
    public static CaseStore Open(string databasePath)
    {
        var dir = Path.GetDirectoryName(databasePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var conn = new SqliteConnection($"Data Source={databasePath}");
        conn.Open();
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = CaseSchema.CreateSql;
            cmd.ExecuteNonQuery();
        }
        return new CaseStore(conn, databasePath);
    }

    /// <summary>Creates a new case row and selects it as the active case.</summary>
    public CaseInfo CreateCase(string name, string? analyst = null, string? description = null)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO Cases (Name, Analyst, Description, CreatedUtc)
                            VALUES ($n, $a, $d, $c); SELECT last_insert_rowid();";
        var created = DateTimeOffset.UtcNow;
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$a", (object?)analyst ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$d", (object?)description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$c", created.ToString("o", CultureInfo.InvariantCulture));
        CaseId = (long)(cmd.ExecuteScalar() ?? 0L);

        return new CaseInfo
        {
            Id = CaseId,
            Name = name,
            Analyst = analyst,
            Description = description,
            CreatedUtc = created,
            DatabasePath = DatabasePath,
        };
    }

    /// <summary>Selects the most recent existing case, or null if none.</summary>
    public CaseInfo? LoadLatestCase()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"SELECT Id, Name, Analyst, Description, CreatedUtc
                            FROM Cases ORDER BY Id DESC LIMIT 1;";
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        CaseId = r.GetInt64(0);
        return new CaseInfo
        {
            Id = CaseId,
            Name = r.GetString(1),
            Analyst = r.IsDBNull(2) ? null : r.GetString(2),
            Description = r.IsDBNull(3) ? null : r.GetString(3),
            CreatedUtc = DateTimeOffset.Parse(r.GetString(4), CultureInfo.InvariantCulture),
            DatabasePath = DatabasePath,
        };
    }

    /// <summary>
    /// Bulk-inserts normalised events (and their raw XML) for the active case in
    /// one transaction. Sets each event's Id to the assigned row id.
    /// </summary>
    public void InsertEvents(IEnumerable<NormalizedEvent> events)
    {
        using var tx = _connection.BeginTransaction();
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"
INSERT INTO NormalizedEvents
(CaseId, TimestampUtc, UnixMs, Hostname, LogSource, EventId, Provider, RecordId, Channel,
 EventType, TargetUserName, TargetDomain, Sid, SourceIp, SourcePort, WorkstationName,
 LogonType, LogonTypeDescription, AuthenticationPackage, LogonProcess, ElevatedToken,
 ImpersonationLevel, ProcessName, ProcessId, TargetServer, ServiceName, GroupName,
 Status, SubStatus, FailureReason, IsSuccess, IsFailure, IsMachineAccount, IsPrivileged, IsRdp)
VALUES
($CaseId, $Ts, $Unix, $Host, $LogSrc, $Eid, $Prov, $Rid, $Chan,
 $Etype, $User, $Dom, $Sid, $Ip, $Port, $Wks,
 $Lt, $Ltd, $Auth, $Lp, $Elev,
 $Imp, $Proc, $Pid, $TServer, $Svc, $Grp,
 $Status, $Sub, $Fail, $Succ, $Failb, $Mach, $Priv, $Rdp);
SELECT last_insert_rowid();";

        var p = cmd.Parameters;
        foreach (var name in new[] { "$CaseId","$Ts","$Unix","$Host","$LogSrc","$Eid","$Prov","$Rid","$Chan",
            "$Etype","$User","$Dom","$Sid","$Ip","$Port","$Wks","$Lt","$Ltd","$Auth","$Lp","$Elev",
            "$Imp","$Proc","$Pid","$TServer","$Svc","$Grp","$Status","$Sub","$Fail",
            "$Succ","$Failb","$Mach","$Priv","$Rdp" })
            p.Add(new SqliteParameter(name, DBNull.Value));

        using var rawCmd = _connection.CreateCommand();
        rawCmd.Transaction = tx;
        rawCmd.CommandText = "INSERT INTO RawEvents (EventRowId, RawXml) VALUES ($id, $xml);";
        rawCmd.Parameters.Add(new SqliteParameter("$id", DBNull.Value));
        rawCmd.Parameters.Add(new SqliteParameter("$xml", DBNull.Value));

        foreach (var e in events)
        {
            p["$CaseId"].Value = CaseId;
            p["$Ts"].Value = e.Timestamp.ToString("o", CultureInfo.InvariantCulture);
            p["$Unix"].Value = e.Timestamp.ToUnixTimeMilliseconds();
            p["$Host"].Value = (object?)e.Hostname ?? DBNull.Value;
            p["$LogSrc"].Value = (object?)e.LogSource ?? DBNull.Value;
            p["$Eid"].Value = e.EventId;
            p["$Prov"].Value = (object?)e.Provider ?? DBNull.Value;
            p["$Rid"].Value = (object?)e.RecordId ?? DBNull.Value;
            p["$Chan"].Value = (object?)e.Channel ?? DBNull.Value;
            p["$Etype"].Value = (object?)e.EventType ?? DBNull.Value;
            p["$User"].Value = (object?)e.TargetUserName ?? DBNull.Value;
            p["$Dom"].Value = (object?)e.TargetDomain ?? DBNull.Value;
            p["$Sid"].Value = (object?)e.Sid ?? DBNull.Value;
            p["$Ip"].Value = (object?)e.SourceIp ?? DBNull.Value;
            p["$Port"].Value = (object?)e.SourcePort ?? DBNull.Value;
            p["$Wks"].Value = (object?)e.WorkstationName ?? DBNull.Value;
            p["$Lt"].Value = (object?)e.LogonType ?? DBNull.Value;
            p["$Ltd"].Value = (object?)e.LogonTypeDescription ?? DBNull.Value;
            p["$Auth"].Value = (object?)e.AuthenticationPackage ?? DBNull.Value;
            p["$Lp"].Value = (object?)e.LogonProcess ?? DBNull.Value;
            p["$Elev"].Value = e.ElevatedToken is null ? DBNull.Value : (e.ElevatedToken.Value ? 1 : 0);
            p["$Imp"].Value = (object?)e.ImpersonationLevel ?? DBNull.Value;
            p["$Proc"].Value = (object?)e.ProcessName ?? DBNull.Value;
            p["$Pid"].Value = (object?)e.ProcessId ?? DBNull.Value;
            p["$TServer"].Value = (object?)e.TargetServer ?? DBNull.Value;
            p["$Svc"].Value = (object?)e.ServiceName ?? DBNull.Value;
            p["$Grp"].Value = (object?)e.GroupName ?? DBNull.Value;
            p["$Status"].Value = (object?)e.Status ?? DBNull.Value;
            p["$Sub"].Value = (object?)e.SubStatus ?? DBNull.Value;
            p["$Fail"].Value = (object?)e.FailureReason ?? DBNull.Value;
            p["$Succ"].Value = e.IsSuccess ? 1 : 0;
            p["$Failb"].Value = e.IsFailure ? 1 : 0;
            p["$Mach"].Value = e.IsMachineAccount ? 1 : 0;
            p["$Priv"].Value = e.IsPrivileged ? 1 : 0;
            p["$Rdp"].Value = e.IsRdp ? 1 : 0;

            var id = (long)(cmd.ExecuteScalar() ?? 0L);
            e.Id = id;
            e.CaseId = CaseId;

            rawCmd.Parameters["$id"].Value = id;
            rawCmd.Parameters["$xml"].Value = (object?)e.RawXml ?? DBNull.Value;
            rawCmd.ExecuteNonQuery();
        }

        tx.Commit();
    }

    public void RecordImportedFile(ImportedFileResult file)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO ImportedFiles
            (CaseId, FilePath, Hostname, LogSource, RecordsRead, EventsNormalised,
             RecordsSkipped, Failed, Error, ImportedUtc)
            VALUES ($c,$f,$h,$l,$rr,$en,$rs,$failed,$err,$utc);";
        cmd.Parameters.AddWithValue("$c", CaseId);
        cmd.Parameters.AddWithValue("$f", file.FilePath);
        cmd.Parameters.AddWithValue("$h", (object?)file.Hostname ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$l", (object?)file.LogSource ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rr", file.RecordsRead);
        cmd.Parameters.AddWithValue("$en", file.EventsNormalised);
        cmd.Parameters.AddWithValue("$rs", file.RecordsSkipped);
        cmd.Parameters.AddWithValue("$failed", file.Failed ? 1 : 0);
        cmd.Parameters.AddWithValue("$err", (object?)file.Error ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$utc", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        cmd.ExecuteNonQuery();
    }

    /// <summary>Queries events for the active case, applying the supplied filter in SQL.</summary>
    public List<NormalizedEvent> QueryEvents(EventFilter? filter = null, int? limit = null)
    {
        var sql = new StringBuilder("SELECT * FROM NormalizedEvents WHERE CaseId = $caseId");
        using var cmd = _connection.CreateCommand();
        cmd.Parameters.AddWithValue("$caseId", CaseId);

        if (filter is not null)
            BuildWhere(filter, sql, cmd);

        sql.Append(" ORDER BY UnixMs ASC");
        if (limit is not null) sql.Append(" LIMIT ").Append(limit.Value);
        cmd.CommandText = sql.ToString();

        var list = new List<NormalizedEvent>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(MapEvent(r));
        return list;
    }

    /// <summary>Returns the raw event XML for a normalised event row.</summary>
    public string? GetRawXml(long eventRowId)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT RawXml FROM RawEvents WHERE EventRowId = $id;";
        cmd.Parameters.AddWithValue("$id", eventRowId);
        var result = cmd.ExecuteScalar();
        return result is string s ? s : null;
    }

    public long AddBookmark(long eventRowId, string? label)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO Bookmarks (CaseId, EventRowId, CreatedUtc, Label)
                            VALUES ($c,$e,$u,$l); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$c", CaseId);
        cmd.Parameters.AddWithValue("$e", eventRowId);
        cmd.Parameters.AddWithValue("$u", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$l", (object?)label ?? DBNull.Value);
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public long AddNote(string text, long? eventRowId = null)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO Notes (CaseId, EventRowId, CreatedUtc, Text)
                            VALUES ($c,$e,$u,$t); SELECT last_insert_rowid();";
        cmd.Parameters.AddWithValue("$c", CaseId);
        cmd.Parameters.AddWithValue("$e", (object?)eventRowId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$u", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$t", text);
        return (long)(cmd.ExecuteScalar() ?? 0L);
    }

    public void InsertFinding(Finding finding)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO Findings
            (CaseId, Severity, RuleName, Description, TimestampUtc, User, SourceIp, Host, RelatedEventIds, Reasoning)
            VALUES ($c,$sev,$rule,$desc,$ts,$user,$ip,$host,$rel,$reason);";
        cmd.Parameters.AddWithValue("$c", CaseId);
        cmd.Parameters.AddWithValue("$sev", (int)finding.Severity);
        cmd.Parameters.AddWithValue("$rule", finding.RuleName);
        cmd.Parameters.AddWithValue("$desc", (object?)finding.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ts", finding.Timestamp.ToString("o", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$user", (object?)finding.User ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ip", (object?)finding.SourceIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$host", (object?)finding.Host ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rel", (object?)finding.RelatedEventIds ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$reason", (object?)finding.Reasoning ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Loads all stored findings for the active case (ordered by severity).</summary>
    public List<Finding> QueryFindings()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"SELECT Severity, RuleName, Description, TimestampUtc, User, SourceIp, Host,
                                   RelatedEventIds, Reasoning
                            FROM Findings WHERE CaseId = $c ORDER BY Severity DESC, TimestampUtc ASC;";
        cmd.Parameters.AddWithValue("$c", CaseId);
        var list = new List<Finding>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(new Finding
            {
                CaseId = CaseId,
                Severity = (FindingSeverity)r.GetInt32(0),
                RuleName = r.GetString(1),
                Description = r.IsDBNull(2) ? string.Empty : r.GetString(2),
                Timestamp = r.IsDBNull(3) ? default : DateTimeOffset.Parse(r.GetString(3), CultureInfo.InvariantCulture),
                User = r.IsDBNull(4) ? null : r.GetString(4),
                SourceIp = r.IsDBNull(5) ? null : r.GetString(5),
                Host = r.IsDBNull(6) ? null : r.GetString(6),
                RelatedEventIds = r.IsDBNull(7) ? null : r.GetString(7),
                Reasoning = r.IsDBNull(8) ? null : r.GetString(8),
            });
        return list;
    }

    /// <summary>True when the active case already has stored events.</summary>
    public bool HasEvents()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT EXISTS(SELECT 1 FROM NormalizedEvents WHERE CaseId = $c);";
        cmd.Parameters.AddWithValue("$c", CaseId);
        return Convert.ToInt64(cmd.ExecuteScalar() ?? 0L) != 0;
    }

    /// <summary>Persists the IOC lists for the active case (replacing any prior row).</summary>
    public void SaveIocs(string? hosts, string? ips, string? users)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"INSERT INTO Iocs (CaseId, Hosts, Ips, Users, UpdatedUtc)
                            VALUES ($c, $h, $i, $u, $t)
                            ON CONFLICT(CaseId) DO UPDATE SET
                                Hosts = excluded.Hosts, Ips = excluded.Ips,
                                Users = excluded.Users, UpdatedUtc = excluded.UpdatedUtc;";
        cmd.Parameters.AddWithValue("$c", CaseId);
        cmd.Parameters.AddWithValue("$h", (object?)hosts ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$i", (object?)ips ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$u", (object?)users ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$t", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        cmd.ExecuteNonQuery();
    }

    /// <summary>Loads the stored IOC lists for the active case (nulls if none saved).</summary>
    public (string? Hosts, string? Ips, string? Users) LoadIocs()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT Hosts, Ips, Users FROM Iocs WHERE CaseId = $c;";
        cmd.Parameters.AddWithValue("$c", CaseId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return (null, null, null);
        return (r.IsDBNull(0) ? null : r.GetString(0),
                r.IsDBNull(1) ? null : r.GetString(1),
                r.IsDBNull(2) ? null : r.GetString(2));
    }

    private static void BuildWhere(EventFilter f, StringBuilder sql, SqliteCommand cmd)
    {
        void Like(string col, string param, string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            sql.Append(" AND ").Append(col).Append(" LIKE ").Append(param);
            cmd.Parameters.AddWithValue(param, "%" + value.Trim() + "%");
        }

        if (f.From is not null) { sql.Append(" AND UnixMs >= $from"); cmd.Parameters.AddWithValue("$from", f.From.Value.ToUnixTimeMilliseconds()); }
        if (f.To is not null) { sql.Append(" AND UnixMs <= $to"); cmd.Parameters.AddWithValue("$to", f.To.Value.ToUnixTimeMilliseconds()); }
        if (f.EventId is not null) { sql.Append(" AND EventId = $eid"); cmd.Parameters.AddWithValue("$eid", f.EventId.Value); }
        if (f.LogonType is not null) { sql.Append(" AND LogonType = $lt"); cmd.Parameters.AddWithValue("$lt", f.LogonType.Value); }
        Like("TargetUserName", "$user", f.User);
        Like("Hostname", "$host", f.Host);
        Like("SourceIp", "$ip", f.SourceIp);
        Like("AuthenticationPackage", "$auth", f.AuthPackage);
        if (f.Success is true) sql.Append(" AND IsSuccess = 1");
        if (f.Success is false) sql.Append(" AND IsFailure = 1");
        if (f.PrivilegedOnly) sql.Append(" AND IsPrivileged = 1");
        if (f.RdpOnly) sql.Append(" AND IsRdp = 1");
        if (f.ExcludeMachineAccounts) sql.Append(" AND IsMachineAccount = 0");
        if (f.ExcludeLocalOrBlankSource)
            sql.Append(" AND SourceIp IS NOT NULL AND SourceIp NOT IN ('-','::1','127.0.0.1','0.0.0.0')");
    }

    private static NormalizedEvent MapEvent(SqliteDataReader r)
    {
        string? S(string c) { var i = r.GetOrdinal(c); return r.IsDBNull(i) ? null : r.GetString(i); }
        long? L(string c) { var i = r.GetOrdinal(c); return r.IsDBNull(i) ? null : r.GetInt64(i); }
        int? I(string c) { var i = r.GetOrdinal(c); return r.IsDBNull(i) ? null : r.GetInt32(i); }
        bool B(string c) { var i = r.GetOrdinal(c); return !r.IsDBNull(i) && r.GetInt64(i) != 0; }
        bool? NB(string c) { var i = r.GetOrdinal(c); return r.IsDBNull(i) ? null : r.GetInt64(i) != 0; }

        return new NormalizedEvent
        {
            Id = r.GetInt64(r.GetOrdinal("Id")),
            CaseId = r.GetInt64(r.GetOrdinal("CaseId")),
            Timestamp = DateTimeOffset.Parse(r.GetString(r.GetOrdinal("TimestampUtc")), CultureInfo.InvariantCulture),
            Hostname = S("Hostname"),
            LogSource = S("LogSource"),
            EventId = r.GetInt32(r.GetOrdinal("EventId")),
            Provider = S("Provider"),
            RecordId = L("RecordId"),
            Channel = S("Channel"),
            EventType = S("EventType") ?? string.Empty,
            TargetUserName = S("TargetUserName"),
            TargetDomain = S("TargetDomain"),
            Sid = S("Sid"),
            SourceIp = S("SourceIp"),
            SourcePort = S("SourcePort"),
            WorkstationName = S("WorkstationName"),
            LogonType = I("LogonType"),
            LogonTypeDescription = S("LogonTypeDescription"),
            AuthenticationPackage = S("AuthenticationPackage"),
            LogonProcess = S("LogonProcess"),
            ElevatedToken = NB("ElevatedToken"),
            ImpersonationLevel = S("ImpersonationLevel"),
            ProcessName = S("ProcessName"),
            ProcessId = S("ProcessId"),
            TargetServer = S("TargetServer"),
            ServiceName = S("ServiceName"),
            GroupName = S("GroupName"),
            Status = S("Status"),
            SubStatus = S("SubStatus"),
            FailureReason = S("FailureReason"),
            IsSuccess = B("IsSuccess"),
            IsFailure = B("IsFailure"),
        };
    }

    public void Dispose()
    {
        _connection.Dispose();
        SqliteConnection.ClearAllPools();
    }
}
