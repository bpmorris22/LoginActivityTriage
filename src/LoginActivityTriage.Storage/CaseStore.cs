using System.Globalization;
using System.Text;
using LoginActivityTriage.Core.Models;
using Microsoft.Data.Sqlite;

namespace LoginActivityTriage.Storage;

/// <summary>
/// Repository over a single case's SQLite database. Owns one connection for the lifetime of
/// the open case. Not thread-safe: callers serialise access (the app only touches it from the
/// import worker while the UI is busy, or from the UI thread otherwise).
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

    /// <summary>Opens (creating if needed) a case database, migrates older schemas and ensures indexes.</summary>
    public static CaseStore Open(string databasePath)
    {
        var dir = Path.GetDirectoryName(databasePath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var conn = new SqliteConnection($"Data Source={databasePath}");
        conn.Open();
        Exec(conn, CaseSchema.CreateSql);
        Migrate(conn);
        Exec(conn, CaseSchema.IndexSql);
        return new CaseStore(conn, databasePath);
    }

    private static void Exec(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Adds columns introduced after a case file was created (ALTER TABLE ADD COLUMN).</summary>
    private static void Migrate(SqliteConnection conn)
    {
        AddMissing(conn, "NormalizedEvents", CaseSchema.EventColumns.Select(c => (c.Name, c.SqlType)), out var addedTechnique);
        AddMissing(conn, "Findings", new[]
        {
            ("Mitre", "TEXT"), ("Count", "INTEGER NOT NULL DEFAULT 1"), ("SessionRef", "INTEGER"),
        }, out _);

        // v0.1 cases flagged RDP by event id only; carry the flag into the technique column.
        if (addedTechnique)
            Exec(conn, "UPDATE NormalizedEvents SET Technique = 'RDP' WHERE IsRdp = 1 AND Technique IS NULL;");
    }

    private static void AddMissing(SqliteConnection conn, string table,
        IEnumerable<(string Name, string Type)> wanted, out bool addedTechnique)
    {
        addedTechnique = false;
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = $"PRAGMA table_info({table});";
            using var r = cmd.ExecuteReader();
            while (r.Read()) existing.Add(r.GetString(1));
        }
        foreach (var (name, type) in wanted)
        {
            if (existing.Contains(name)) continue;
            Exec(conn, $"ALTER TABLE {table} ADD COLUMN {name} {type};");
            if (name == "Technique") addedTechnique = true;
        }
    }

    // ------------------------------------------------------------------ cases

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

    // ------------------------------------------------------------------ events

    /// <summary>
    /// Bulk-inserts normalised events (and their raw XML) for the active case in one
    /// transaction. Sets each inserted event's Id. Events whose dedupe key already exists in
    /// the case are skipped. Returns the number of rows inserted.
    /// </summary>
    /// <param name="dropRawXmlAfterInsert">Release the raw XML from memory once it is stored.</param>
    public int InsertEvents(IEnumerable<NormalizedEvent> events, bool dropRawXmlAfterInsert = false)
    {
        var cols = CaseSchema.EventColumns;
        using var tx = _connection.BeginTransaction();
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText =
            $"INSERT INTO NormalizedEvents (CaseId, TimestampUtc, UnixMs, {string.Join(", ", cols.Select(c => c.Name))}) " +
            $"VALUES ($CaseId, $Ts, $Unix, {string.Join(", ", cols.Select((_, i) => "$p" + i))}) " +
            "ON CONFLICT(CaseId, DedupeKey) DO NOTHING RETURNING Id;";

        var caseP = cmd.Parameters.Add(new SqliteParameter("$CaseId", CaseId));
        var tsP = cmd.Parameters.Add(new SqliteParameter("$Ts", DBNull.Value));
        var unixP = cmd.Parameters.Add(new SqliteParameter("$Unix", DBNull.Value));
        var ps = cols.Select((_, i) => cmd.Parameters.Add(new SqliteParameter("$p" + i, DBNull.Value))).ToArray();

        using var rawCmd = _connection.CreateCommand();
        rawCmd.Transaction = tx;
        rawCmd.CommandText = "INSERT INTO RawEvents (EventRowId, RawXml) VALUES ($id, $xml);";
        var idP = rawCmd.Parameters.Add(new SqliteParameter("$id", DBNull.Value));
        var xmlP = rawCmd.Parameters.Add(new SqliteParameter("$xml", DBNull.Value));

        var inserted = 0;
        foreach (var e in events)
        {
            tsP.Value = e.Timestamp.ToString("o", CultureInfo.InvariantCulture);
            unixP.Value = e.Timestamp == DateTimeOffset.MinValue ? 0L : e.Timestamp.ToUnixTimeMilliseconds();
            for (var i = 0; i < cols.Count; i++) ps[i].Value = cols[i].Get(e) ?? DBNull.Value;

            var result = cmd.ExecuteScalar();
            if (result is null or DBNull) continue; // duplicate
            var id = Convert.ToInt64(result, CultureInfo.InvariantCulture);
            e.Id = id;
            e.CaseId = CaseId;
            inserted++;

            idP.Value = id;
            xmlP.Value = (object?)e.RawXml ?? DBNull.Value;
            rawCmd.ExecuteNonQuery();
            if (dropRawXmlAfterInsert) e.RawXml = null;
        }

        tx.Commit();
        return inserted;
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

    /// <summary>
    /// Queries events for the active case. Coarse criteria are applied in SQL; the filter's
    /// own <see cref="EventFilter.Matches"/> then gives the exact semantics (CIDR, user OR
    /// subject, derived flags) so SQL and in-memory filtering always agree.
    /// </summary>
    public List<NormalizedEvent> QueryEvents(EventFilter? filter = null, int? limit = null)
    {
        var sql = new StringBuilder(
            $"SELECT Id, CaseId, TimestampUtc, {string.Join(", ", CaseSchema.EventColumns.Where(c => c.Set is not null).Select(c => c.Name))} " +
            "FROM NormalizedEvents WHERE CaseId = $caseId");
        using var cmd = _connection.CreateCommand();
        cmd.Parameters.AddWithValue("$caseId", CaseId);

        if (filter is not null)
        {
            if (filter.From is not null) { sql.Append(" AND UnixMs >= $from"); cmd.Parameters.AddWithValue("$from", filter.From.Value.ToUnixTimeMilliseconds()); }
            if (filter.To is not null) { sql.Append(" AND UnixMs <= $to"); cmd.Parameters.AddWithValue("$to", filter.To.Value.ToUnixTimeMilliseconds()); }
            if (filter.EventId is not null) { sql.Append(" AND EventId = $eid"); cmd.Parameters.AddWithValue("$eid", filter.EventId.Value); }
            if (filter.LogonType is not null) { sql.Append(" AND LogonType = $lt"); cmd.Parameters.AddWithValue("$lt", filter.LogonType.Value); }
            if (filter.Success is true) sql.Append(" AND IsSuccess = 1");
            if (filter.Success is false) sql.Append(" AND IsFailure = 1");
        }

        sql.Append(" ORDER BY UnixMs ASC, Id ASC");
        if (limit is not null && (filter is null || filter.IsEmpty)) sql.Append(" LIMIT ").Append(limit.Value);
        cmd.CommandText = sql.ToString();

        var settable = CaseSchema.EventColumns.Where(c => c.Set is not null).ToArray();
        var list = new List<NormalizedEvent>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var e = new NormalizedEvent
            {
                Id = r.GetInt64(0),
                CaseId = r.GetInt64(1),
                Timestamp = DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal),
            };
            for (var i = 0; i < settable.Length; i++)
                settable[i].Set!(e, r.IsDBNull(i + 3) ? null : r.GetValue(i + 3));
            if (filter is null || filter.Matches(e)) list.Add(e);
            if (limit is not null && list.Count >= limit) break;
        }
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

    // ------------------------------------------------------------------ findings

    /// <summary>Replaces every stored finding of the active case (analytics are recomputed, never appended).</summary>
    public void ReplaceFindings(IEnumerable<Finding> findings)
    {
        using var tx = _connection.BeginTransaction();
        using (var del = _connection.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM Findings WHERE CaseId = $c;";
            del.Parameters.AddWithValue("$c", CaseId);
            del.ExecuteNonQuery();
        }
        foreach (var f in findings) InsertFinding(f, tx);
        tx.Commit();
    }

    public void InsertFinding(Finding finding) => InsertFinding(finding, null);

    private void InsertFinding(Finding finding, SqliteTransaction? tx)
    {
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = @"INSERT INTO Findings
            (CaseId, Severity, RuleName, Description, TimestampUtc, User, SourceIp, Host, RelatedEventIds, Reasoning, Mitre, Count, SessionRef)
            VALUES ($c,$sev,$rule,$desc,$ts,$user,$ip,$host,$rel,$reason,$mitre,$count,$sref);";
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
        cmd.Parameters.AddWithValue("$mitre", (object?)finding.Mitre ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$count", finding.Count);
        cmd.Parameters.AddWithValue("$sref", (object?)finding.SessionRef ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>Loads all stored findings for the active case (ordered by severity).</summary>
    public List<Finding> QueryFindings()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = @"SELECT Severity, RuleName, Description, TimestampUtc, User, SourceIp, Host,
                                   RelatedEventIds, Reasoning, Mitre, Count, SessionRef
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
                Mitre = r.IsDBNull(9) ? null : r.GetString(9),
                Count = r.IsDBNull(10) ? 1 : r.GetInt32(10),
                SessionRef = r.IsDBNull(11) ? null : r.GetInt32(11),
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

    // ------------------------------------------------------------------ IOCs

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

    public void Dispose()
    {
        _connection.Dispose();
        SqliteConnection.ClearAllPools();
    }
}
