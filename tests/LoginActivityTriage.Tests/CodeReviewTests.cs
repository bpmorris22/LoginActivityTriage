using System.Diagnostics;
using System.IO;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Regression tests for the external code review of 2026-10-03 (CODE_REVIEW_2026-10-03.md): each
/// reproduced defect's probe, plus the behaviour that must survive the fix.
/// </summary>
public class CodeReviewTests
{
    private static readonly DateTimeOffset T = DateTimeOffset.Parse("2026-09-14T08:00:00Z");

    private static NormalizedEvent E(int id, int sec = 0, string host = "SERVER") =>
        new() { EventId = id, Timestamp = T.AddSeconds(sec), Hostname = host, RecordId = sec * 10 + id };

    private static NormalizedEvent RdpAttempt(int sec, string target)
    {
        var e = E(1024, sec);
        e.IsOutbound = true; e.Technique = RemoteTechnique.Rdp; e.TargetServer = target;
        return e;
    }

    private static NormalizedEvent HandOff(int sec, string server, string process = "C:\\Windows\\System32\\lsass.exe", string? technique = null)
    {
        var e = E(4648, sec);
        e.SubjectUserName = "alice"; e.SubjectDomain = "DOMAIN"; e.TargetUserName = "administrator"; e.TargetDomain = "DOMAIN";
        e.TargetServer = server; e.ProcessName = process; e.Technique = technique; e.IsOutbound = technique is not null;
        return e;
    }

    // #4 -----------------------------------------------------------------------------------------

    [Fact]
    public void OutboundAttempt_DoesNotClaimAnotherTechniquesHandOff()
    {
        var sessions = new RemoteSessionBuilder().Build(new[] { RdpAttempt(0, "10.1.1.10"), HandOff(2, "unrelated-server", "", RemoteTechnique.PsRemoting) });
        var rdp = Assert.Single(sessions, s => s.Technique == RemoteTechnique.Rdp);
        Assert.Null(rdp.TargetHostName);
        Assert.Null(rdp.User);
        Assert.NotEqual("High", rdp.Confidence);
        Assert.Single(sessions, s => s.Technique == RemoteTechnique.PsRemoting); // the WinRM hand-off keeps its own session
    }

    [Fact]
    public void RdpNameForAddress_IsMedium_UntilCorroborated_AndWithdrawnWhenConflicting()
    {
        var once = new RemoteSessionBuilder().Build(new[] { RdpAttempt(0, "10.10.20.33"), HandOff(7, "SQL01.contoso.local") }).Single();
        Assert.Equal("SQL01.contoso.local", once.TargetHostName);
        Assert.Equal("Medium", once.Confidence);
        Assert.Contains("matched by time and lsass.exe only", once.Evidence);

        var twice = new RemoteSessionBuilder().Build(new[]
        {
            RdpAttempt(0, "10.10.20.33"), HandOff(7, "SQL01.contoso.local"),
            RdpAttempt(600, "10.10.20.33"), HandOff(607, "SQL01.contoso.local"),
        });
        Assert.All(twice, s => Assert.Equal("High", s.Confidence));
        Assert.All(twice, s => Assert.Contains("corroborated by 2 connections", s.Evidence));

        var conflict = new RemoteSessionBuilder().Build(new[]
        {
            RdpAttempt(0, "10.10.20.33"), HandOff(7, "SQL01.contoso.local"),
            RdpAttempt(600, "10.10.20.33"), HandOff(607, "FILESRV.contoso.local"),
        });
        Assert.All(conflict, s => Assert.Null(s.TargetHostName));
        Assert.All(conflict, s => Assert.Contains("name withdrawn", s.Evidence));

        // A hand-off from an unrelated process, or naming another address, is not taken at all.
        Assert.Null(new RemoteSessionBuilder().Build(new[] { RdpAttempt(0, "10.10.20.33"), HandOff(7, "SQL01", "C:\\x\\tool.exe") })
            .Single(s => s.Technique == RemoteTechnique.Rdp).User);
        Assert.Null(new RemoteSessionBuilder().Build(new[] { RdpAttempt(0, "10.10.20.33"), HandOff(7, "10.10.20.34") })
            .Single(s => s.Technique == RemoteTechnique.Rdp).User);
    }

    // #5 -----------------------------------------------------------------------------------------

    [Fact]
    public void SimultaneousShellsOfDifferentLogons_StaySeparate()
    {
        var a = E(4624); a.TargetUserName = "alice"; a.LogonId = "0xa"; a.LogonType = 3; a.SourceIp = "10.1.1.1";
        var b = E(4624, 5); b.TargetUserName = "bob"; b.LogonId = "0xb"; b.LogonType = 3; b.SourceIp = "10.1.1.2";
        var pa = E(4688, 1); pa.Technique = RemoteTechnique.PsRemoting; pa.LogonId = "0xa"; pa.TargetUserName = "alice"; pa.CommandLine = "alice-command";
        var pb = E(4688, 6); pb.Technique = RemoteTechnique.PsRemoting; pb.LogonId = "0xb"; pb.TargetUserName = "bob"; pb.CommandLine = "bob-command";
        // An event without a logon id (WinRM 91) for bob joins bob's session, not alice's.
        var w = E(91, 7); w.Technique = RemoteTechnique.PsRemoting; w.TargetUserName = "bob";

        var sessions = new RemoteSessionBuilder().Build(new[] { a, b, pa, pb, w });
        Assert.Equal(2, sessions.Count);
        var alice = sessions.Single(s => s.User == "alice");
        var bob = sessions.Single(s => s.User == "bob");
        Assert.Equal("alice-command", alice.Commands);
        Assert.Equal("bob-command", bob.Commands);
        Assert.Equal("10.1.1.2", bob.SourceIp);
        Assert.Contains("91", bob.EventIds);
    }

    // #6 -----------------------------------------------------------------------------------------

    [Fact]
    public void LogonIdReusedAfterReboot_LinksNoProcessToTheOldSession()
    {
        var old = E(4624); old.LogonType = 3; old.LogonId = "0xabc"; old.TargetUserName = "alice";
        var boot = E(6005, 100);
        var p = E(4688, 200); p.KeepOnlyIfLinked = true; p.LogonId = "0xabc"; p.TargetUserName = "bob";
        Assert.DoesNotContain(p, ProcessEventFilter.Apply(new[] { old, boot, p }));

        // Same logon without a reboot: the process is kept.
        var p2 = E(4688, 200); p2.KeepOnlyIfLinked = true; p2.LogonId = "0xabc";
        Assert.Contains(p2, ProcessEventFilter.Apply(new[] { old, p2 }));

        var ra = E(4624); ra.TargetUserName = "alice"; ra.LogonId = "0xabc"; ra.LogonType = 10; ra.Technique = RemoteTechnique.Rdp; ra.SourceIp = "10.1.1.1";
        var ro = E(4634, 50); ro.TargetUserName = "alice"; ro.LogonId = "0xabc"; ro.LogonType = 10;
        var reboot = E(6005, 100);
        var local = E(4624, 150); local.TargetUserName = "bob"; local.LogonId = "0xabc"; local.LogonType = 2;
        var bp = E(4688, 200); bp.TargetUserName = "bob"; bp.LogonId = "0xabc"; bp.CommandLine = "bob-local-command";
        // Even unfiltered, the closed, pre-reboot RDP session does not absorb the later process.
        var rdp = Assert.Single(new RemoteSessionBuilder().Build(new[] { ra, ro, reboot, local, bp }));
        Assert.Null(rdp.Commands);
        Assert.Equal(T.AddSeconds(50), rdp.End);
    }

    [Fact]
    public void RdpReconnect_TransientAuthLogoff_DoesNotEndTheSession()
    {
        // FS01.contoso.local 2026-09-16 14:30-14:50: disconnect, reconnect with a new type-10 auth logon
        // (logged off at 14:36:52), then the session's own logoff at 14:50:26 (4647 + LSM 23).
        NormalizedEvent Ev(int id, int sec, string? logon = null, int? type = null, string? session = null)
        {
            var e = E(id, sec, "GE-3"); e.TargetUserName = "administrator"; e.LogonId = logon; e.LogonType = type; e.SessionId = session;
            if (id is 24 or 25 or 1149 or 4778 or 4779) e.Technique = RemoteTechnique.Rdp;
            if (id == 1149) e.SourceIp = "10.10.20.9";
            return e;
        }
        var events = new[]
        {
            Ev(1149, 0), Ev(4624, 1, "0x2d57b", 10), Ev(21, 3, session: "1"),
            Ev(4779, 60, "0x2d57b"), Ev(24, 60, session: "1"),
            Ev(1149, 315), Ev(4624, 316, "0x35e96e", 10), Ev(4778, 317, "0x2d57b"), Ev(25, 317, session: "1"),
            Ev(4634, 420, "0x35e96e", 10),
            Ev(4647, 1194, "0x2d57b"), Ev(23, 1194, session: "1"),
        };
        events[2].Technique = RemoteTechnique.Rdp;
        var s = Assert.Single(new RemoteSessionBuilder().Build(events));
        Assert.Equal(T.AddSeconds(1194), s.End);
        Assert.Contains("4647", s.EventIds);
        Assert.Contains("23", s.EventIds);
        Assert.Contains("logged off", s.Detail);
    }

    [Theory]
    [InlineData(true, "WS-ANALYST7")]
    [InlineData(false, null)]
    public void RdpSourceHost_IsNeverTheServerItself(bool withReconnect, string? expected)
    {
        // Under NLA the 4624 type 10 WorkstationName is the RDP server's own name; 4778 ClientName is the client.
        NormalizedEvent Ev(int id, int sec, string? workstation = null)
        {
            var e = E(id, sec, "GE-3.contoso.local"); e.TargetUserName = "administrator"; e.LogonId = "0x2d57b";
            e.SourceIp = "10.10.20.9"; e.WorkstationName = workstation;
            if (id is 1149 or 4778 or 4779) e.Technique = RemoteTechnique.Rdp;
            if (id == 4624) e.LogonType = 10;
            return e;
        }
        var events = new List<NormalizedEvent> { Ev(1149, 0), Ev(4624, 1, "GE-3") };
        if (withReconnect) { events.Add(Ev(4779, 60, "WS-ANALYST7")); events.Add(Ev(4778, 300, "WS-ANALYST7")); }
        var s = Assert.Single(new RemoteSessionBuilder().Build(events));
        Assert.Equal(expected, s.SourceHost);
    }

    // #7 -----------------------------------------------------------------------------------------

    private static string Share5145(string relative, string mask, string list, string keywords = "0x8020000000000000") =>
        $"""<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>5145</EventID><TimeCreated SystemTime="2026-09-14T08:00:00Z"/><Keywords>{keywords}</Keywords><Channel>Security</Channel><Computer>SERVER</Computer></System><EventData><Data Name="SubjectUserName">alice</Data><Data Name="SubjectLogonId">0x123</Data><Data Name="IpAddress">10.1.1.1</Data><Data Name="ShareName">\\*\ADMIN$</Data><Data Name="RelativeTargetName">{relative}</Data><Data Name="AccessMask">{mask}</Data><Data Name="AccessList">{list}</Data></EventData></Event>""";

    [Fact]
    public void ShareAccess_IsAWriteOnlyWhenWriteRightsWereGranted()
    {
        var n = new EventNormalizer();
        Assert.Null(n.Normalize(Share5145("tools\\inventory.exe", "0x1", "%%4416"), new NormalizationContext())); // read-only: routine

        var write = n.Normalize(Share5145("tools\\inventory.exe", "0x2", "%%4417"), new NormalizationContext())!;
        Assert.Equal(RemoteTechnique.AdminShare, write.Technique);
        var f = Assert.Single(new SuspiciousSequenceAnalyzer().Run(new[] { write }).Findings);
        Assert.Equal("Write access to executable on admin share", f.RuleName);

        var denied = n.Normalize(Share5145("tools\\inventory.exe", "0x2", "%%4417", "0x8010000000000000"), new NormalizationContext())!;
        Assert.Null(denied.Technique);
        Assert.Contains("access DENIED", denied.Details);

        // Impacket wmiexec / smbexec output is READ back by the attacker: read access still counts.
        var output = n.Normalize(Share5145("__1696248000.123456", "0x1", "%%4416"), new NormalizationContext())!;
        Assert.Equal(RemoteTechnique.Wmi, output.Technique);
    }

    // #8 -----------------------------------------------------------------------------------------

    private static List<NormalizedEvent> FailuresThenSuccess(string failDomain, string? okDomain)
    {
        var list = Enumerable.Range(0, 3).Select(i =>
        {
            var f = E(4625, i); f.TargetUserName = "administrator"; f.TargetDomain = failDomain; f.SourceIp = "10.10.3.4"; f.IsFailure = true;
            return f;
        }).ToList();
        var ok = E(4624, 4); ok.TargetUserName = "administrator"; ok.TargetDomain = okDomain; ok.SourceIp = "10.10.3.4"; ok.IsSuccess = true; ok.LogonType = 3;
        list.Add(ok);
        return list;
    }

    [Fact]
    public void AccountsWithTheSameNameInDifferentDomains_AreDifferentAccounts()
    {
        static IEnumerable<Finding> Guessing(List<NormalizedEvent> ev) =>
            new SuspiciousSequenceAnalyzer().Run(ev).Findings.Where(f => f.RuleName == "Failed logons followed by success");

        Assert.Empty(Guessing(FailuresThenSuccess("DOMAIN-A", "DOMAIN-B")));
        var users = PivotBuilder.ByUser(FailuresThenSuccess("DOMAIN-A", "DOMAIN-B")).ToList();
        Assert.Equal(2, users.Count);
        Assert.Contains(users, u => u.User == "DOMAIN-A\\administrator" && u.Failed == 3 && u.Successful == 0);
        Assert.Contains(users, u => u.User == "DOMAIN-B\\administrator" && u.Successful == 1);

        // Same account: NetBIOS vs FQDN domain, or a domain left out, still matches.
        Assert.Single(Guessing(FailuresThenSuccess("CONTOSO", "contoso.local")));
        Assert.Single(Guessing(FailuresThenSuccess("CONTOSO", null)));
        Assert.Equal("administrator", Assert.Single(PivotBuilder.ByUser(FailuresThenSuccess("CONTOSO", "contoso.local"))).User);

        Assert.True(AccountKey.SameAccount("CONTOSO\\jdoe", null, "jdoe", "contoso.local"));
        Assert.False(AccountKey.SameAccount("administrator", "CONTOSO", "administrator", "SERVER01"));
        // A SID-named group member is one identity whatever group domain is logged beside it.
        Assert.True(AccountKey.SameAccount("S-1-5-21-1-2-3-1010", "BUILTIN", "S-1-5-21-1-2-3-1010", "SQL01"));
        var member = new[] { "BUILTIN", "SQL01" }.Select((d, i) => { var x = E(4732, i); x.TargetUserName = "S-1-5-21-1-2-3-1010"; x.TargetDomain = d; return x; });
        Assert.Single(PivotBuilder.ByUser(member));
    }

    // #2 -----------------------------------------------------------------------------------------

    [Fact]
    public void AFileThatIsNotAnEventLog_IsReportedAsFailed()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lat-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var bad = Path.Combine(dir, "bad.evtx");
            File.WriteAllText(bad, "not an evtx");
            var summary = new EvtxImporter().Import(bad, _ => { });
            Assert.Equal(1, summary.FilesFailed);
            Assert.True(summary.Files[0].Failed);
            Assert.Contains("Not a readable event log", summary.Files[0].Error);
            Assert.NotEmpty(summary.Errors);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    // #9 -----------------------------------------------------------------------------------------

    [Fact]
    public void OutboundCorrelation_ScalesLinearly()
    {
        var events = new List<NormalizedEvent>();
        for (var i = 0; i < 40000; i++) events.Add(RdpAttempt(i * 60, "10.1.1.10"));
        var sw = Stopwatch.StartNew();
        var sessions = new RemoteSessionBuilder().Build(events);
        sw.Stop();
        Assert.Equal(40000, sessions.Count);
        // The quadratic version needed ~4.5 s for 32,000 attempts on the review machine.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3), $"took {sw.Elapsed.TotalSeconds:0.00}s");
    }
}
