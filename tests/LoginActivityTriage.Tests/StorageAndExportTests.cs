using System.IO;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Export;
using LoginActivityTriage.Parsing;
using LoginActivityTriage.Storage;
using Microsoft.Data.Sqlite;
using Xunit;

namespace LoginActivityTriage.Tests;

public class StorageAndExportTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "lat-tests-" + Guid.NewGuid().ToString("N"));

    public StorageAndExportTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private static NormalizedEvent Sample(long record, string user = "jdoe") => new()
    {
        Timestamp = new DateTimeOffset(2026, 6, 20, 10, 0, 0, TimeSpan.Zero).AddSeconds(record),
        Hostname = "SRV01",
        Channel = "Security",
        EventId = 4624,
        RecordId = record,
        TargetUserName = user,
        LogonType = 3,
        LogonId = "0xabc",
        Technique = RemoteTechnique.PsExec,
        IsSuccess = true,
        RawXml = "<Event/>",
    };

    [Fact]
    public void InsertEvents_SkipsDuplicates_AndRoundTripsNewFields()
    {
        var path = Path.Combine(_dir, "case.latdb");
        using (var store = CaseStore.Open(path))
        {
            store.CreateCase("t");
            Assert.Equal(2, store.InsertEvents(new[] { Sample(1), Sample(2) }));
            Assert.Equal(0, store.InsertEvents(new[] { Sample(1) }));   // same dedupe key
        }

        using var reopened = CaseStore.Open(path);
        reopened.LoadLatestCase();
        var events = reopened.QueryEvents();
        Assert.Equal(2, events.Count);
        Assert.Equal("0xabc", events[0].LogonId);
        Assert.Equal(RemoteTechnique.PsExec, events[0].Technique);
        Assert.Equal(TimeSpan.Zero, events[0].Timestamp.Offset);
        Assert.Equal("<Event/>", reopened.GetRawXml(events[0].Id));
    }

    [Fact]
    public void ReplaceFindings_DoesNotAccumulate()
    {
        using var store = CaseStore.Open(Path.Combine(_dir, "f.latdb"));
        store.CreateCase("t");
        var f = new Finding { RuleName = "r", Severity = FindingSeverity.High, Timestamp = DateTimeOffset.UtcNow, Mitre = "T1047", Count = 3 };
        store.ReplaceFindings(new[] { f });
        store.ReplaceFindings(new[] { f });
        var stored = store.QueryFindings();
        var one = Assert.Single(stored);
        Assert.Equal("T1047", one.Mitre);
        Assert.Equal(3, one.Count);
    }

    [Fact]
    public void OldCaseDatabase_IsMigrated()
    {
        var path = Path.Combine(_dir, "old.latdb");
        using (var conn = new SqliteConnection($"Data Source={path}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            // v0.1 schema subset.
            cmd.CommandText = @"
CREATE TABLE Cases (Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Analyst TEXT, Description TEXT, CreatedUtc TEXT NOT NULL);
CREATE TABLE NormalizedEvents (Id INTEGER PRIMARY KEY AUTOINCREMENT, CaseId INTEGER NOT NULL, TimestampUtc TEXT NOT NULL,
  UnixMs INTEGER NOT NULL, Hostname TEXT, EventId INTEGER NOT NULL, TargetUserName TEXT, IsSuccess INTEGER NOT NULL DEFAULT 0,
  IsFailure INTEGER NOT NULL DEFAULT 0, IsRdp INTEGER NOT NULL DEFAULT 0);
CREATE TABLE Findings (Id INTEGER PRIMARY KEY AUTOINCREMENT, CaseId INTEGER NOT NULL, Severity INTEGER NOT NULL, RuleName TEXT NOT NULL,
  Description TEXT, TimestampUtc TEXT, User TEXT, SourceIp TEXT, Host TEXT, RelatedEventIds TEXT, Reasoning TEXT);
INSERT INTO Cases (Name, CreatedUtc) VALUES ('old', '2026-06-01T00:00:00.0000000+00:00');
INSERT INTO NormalizedEvents (CaseId, TimestampUtc, UnixMs, Hostname, EventId, TargetUserName, IsRdp)
  VALUES (1, '2026-06-01T10:00:00.0000000+00:00', 1780308000000, 'TS01', 21, 'jdoe', 1);";
            cmd.ExecuteNonQuery();
        }
        SqliteConnection.ClearAllPools();

        using var store = CaseStore.Open(path);
        store.LoadLatestCase();
        var e = Assert.Single(store.QueryEvents());
        Assert.Equal(RemoteTechnique.Rdp, e.Technique);
        Assert.True(e.IsRdp);
    }

    [Theory]
    [InlineData("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0")]
    [InlineData("+SUM(1,1)", "\"'+SUM(1,1)\"")]
    [InlineData("@evil", "'@evil")]
    [InlineData("-2+3", "'-2+3")]
    [InlineData("jdoe", "jdoe")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    public void CsvEscape_NeutralisesFormulas(string input, string expected) =>
        Assert.Equal(expected, CsvExporter.Escape(input));

    [Fact]
    public void CsvTimestamps_AreUtcWithZ()
    {
        var csv = CsvExporter.ToCsvString(new[] { Sample(1) });
        Assert.Contains("2026-06-20T10:00:01.000Z", csv);
    }

    [Theory]
    [InlineData("10.0.0.10", "10.0.0.1", false)]
    [InlineData("10.0.0.1", "10.0.0.1", true)]
    [InlineData("10.0.0.10", "10.0.0.0/24", true)]
    [InlineData("10.0.1.10", "10.0.0.0/24", false)]
    [InlineData("192.168.4.20", "192.168.*", true)]
    [InlineData("172.16.9.9", "16.9", true)]
    public void IpFilter_ExactCidrPrefixSubstring(string ip, string filter, bool expected) =>
        Assert.Equal(expected, IpUtil.MatchesFilter(ip, filter));

    [Fact]
    public void PositionalData_IsReadable()
    {
        var x = EventXml.Positional("PowerShell", "Windows PowerShell", 400, EventXml.T0, "H", "a", "b", "c");
        var d = EventXmlData.TryParse(x)!;
        Assert.Equal(3, d.PositionalCount);
        Assert.Equal("c", d.GetPositional(2));
    }

    [Theory]
    [InlineData(@"D:\Cases\KAPE\HOST01\C\Windows\System32\winevt\Logs\Security.evtx", "HOST01")]
    [InlineData(@"D:\Cases\HOST02\Security.evtx", "HOST02")]
    [InlineData(@"E:\out\HOST03\uploads\auto\C%3A\Windows\System32\winevt\Logs\System.evtx", "HOST03")]
    public void HostnameInference_SkipsGenericFolders(string path, string expected) =>
        Assert.Equal(expected, EvtxImporter.InferHostname(path));

    [Theory]
    [InlineData("Microsoft-Windows-WinRM%4Operational.evtx", "WinRM")]
    [InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "TerminalServices-LSM")]
    [InlineData("Windows PowerShell.evtx", "Windows PowerShell")]
    [InlineData("Microsoft-Windows-PowerShell%4Operational.evtx", "PowerShell-Operational")]
    public void LogSourceInference_DecodesChannelNames(string file, string expected) =>
        Assert.Equal(expected, EvtxImporter.InferLogSource(file));

    [Fact]
    public void IocSet_MatchesSourceWorkstationAndSubject()
    {
        var iocs = new IocSet();
        iocs.Set("WKS07", null, "adm_jdoe");
        Assert.True(iocs.Matches(new NormalizedEvent { Hostname = "SRV01", WorkstationName = "WKS07" }));
        Assert.True(iocs.Matches(new NormalizedEvent { Hostname = "SRV01", SubjectUserName = "CONTOSO\\adm_jdoe" }));
        Assert.False(iocs.Matches(new NormalizedEvent { Hostname = "SRV01", TargetUserName = "bob" }));
    }
}
