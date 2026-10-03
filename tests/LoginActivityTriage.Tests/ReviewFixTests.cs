using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Export;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Regression tests for the WS-0142 results review (2026-10-03, second pass): split outbound
/// targets, WinRM noise in the triage timeline, explicit-credential counts on the wrong account,
/// after-hours without the weekday, SYSTEM rows / blank users, RMM counted as remote execution,
/// unattributed outbound sessions, console failed-then-success, and the remote-host pivot.
/// </summary>
public class ReviewFixTests
{
    private readonly EventNormalizer _n = new();
    private static readonly NormalizationContext Ctx = new();
    private const string Host = "WS-0142.contoso.local";
    private const string G = "S-1-5-21-9-9-9-4809";

    /// <summary>Saturday 2026-09-12 02:51:21Z = 10:51 at UTC+8 on the host.</summary>
    private static readonly DateTimeOffset Sat = new(2026, 9, 12, 2, 51, 21, TimeSpan.Zero);

    private List<NormalizedEvent> Normalize(params string[] xml) =>
        ProcessEventFilter.Apply(xml.Select(x => _n.Normalize(x, Ctx)).Where(e => e is not null).Select(e => e!).ToList());

    private static string RdpClient(int id, DateTimeOffset t, string name, string value) =>
        Event("Microsoft-Windows-TerminalServices-ClientActiveXCore", "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            id, t, Host, new[] { ("Name", name), ("Value", value), ("CustomLevel", "Info") });

    private static string Explicit(DateTimeOffset t, string subject, string targetUser, string server) =>
        Sec(4648, t, Host, ("SubjectUserSid", G), ("SubjectUserName", subject), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", "0x47a1ede"), ("TargetUserName", targetUser), ("TargetDomainName", "contoso"),
            ("TargetServerName", server), ("TargetInfo", server), ("ProcessName", "C:\\Windows\\System32\\lsass.exe"), ("IpAddress", "-"));

    private static string Console(DateTimeOffset t, int type, string logonId, string user = "jdoe") =>
        Sec(4624, t, Host, ("TargetUserSid", G), ("TargetUserName", user), ("TargetDomainName", "CONTOSO"),
            ("TargetLogonId", logonId), ("LogonType", type.ToString()), ("IpAddress", "127.0.0.1"),
            ("AuthenticationPackageName", "Negotiate"), ("ElevatedToken", "%%1843"));

    // Real 4625s carry the NULL SID for the target account (as on WS-0142).
    private static string BadPassword(DateTimeOffset t, int type = 2) =>
        Sec(4625, t, Host, ("TargetUserSid", "S-1-0-0"), ("TargetUserName", "jdoe"), ("TargetDomainName", "CONTOSO"), ("Status", "0xc000006d"),
            ("SubStatus", "0xc000006a"), ("LogonType", type.ToString()), ("AuthenticationPackageName", "Negotiate"),
            ("IpAddress", "127.0.0.1"), ("IpPort", "0"));

    private static string Zone(DateTimeOffset t) =>
        Positional("EventLog", "System", 6013, t, Host, "", "", "", "", "14", "60", "-480 台北標準時間");

    // 1 -----------------------------------------------------------------------------------------

    [Fact]
    public void OutboundRdpFinding_ListsEachTargetOnce_WithItsResolvedName()
    {
        var events = Normalize(
            RdpClient(1024, T0, "Server Name", "10.10.20.33"),
            RdpClient(1024, T0.AddMinutes(10), "Server Name", "10.10.20.33"),
            RdpClient(1024, T0.AddMinutes(20), "Server Name", "10.10.20.33"),
            Explicit(T0.AddMinutes(20).AddSeconds(7), "jdoe", "administrator", "SQL01.contoso.local"),
            RdpClient(1024, T0.AddMinutes(30), "Server Name", "10.10.20.34"));

        var f = Assert.Single(new SuspiciousSequenceAnalyzer().Run(events).Findings, x => x.RuleName == "Outbound RDP from this host");
        Assert.Contains("10.10.20.33 (SQL01.contoso.local) x3", f.Description);
        Assert.DoesNotContain("10.10.20.33 x", f.Description);
        Assert.Contains("10.10.20.34 x1", f.Description);
        Assert.Contains("by CONTOSO\\jdoe using contoso\\administrator (1)", f.Description);
    }

    // 2 -----------------------------------------------------------------------------------------

    [Fact]
    public void WinRmClientErrorsOutsideASession_StayOutOfTheTriageTimeline()
    {
        var e161 = _n.Normalize(Event(WinRm, "Microsoft-Windows-WinRM/Operational", 161, T0, Host,
            new[] { ("authFailureMessage", "The client cannot connect to the destination specified in the request.") }), Ctx)!;
        var e142 = _n.Normalize(Event(WinRm, "Microsoft-Windows-WinRM/Operational", 142, T0, Host,
            new[] { ("operationName", "Enumeration"), ("errorCode", "2150858770") }), Ctx)!;
        Assert.False(TriageTimeline.Include(e161));
        Assert.False(TriageTimeline.Include(e142));
        e142.RemoteSessionRef = 7; // part of a stitched session: kept
        Assert.True(TriageTimeline.Include(e142));
    }

    // 3 -----------------------------------------------------------------------------------------

    [Fact]
    public void ExplicitCredentials_CountForTheAccountThatUsedThem_AndTheOwner()
    {
        var events = Normalize(
            Console(T0, 2, "0x47a1ede"),
            Explicit(T0.AddMinutes(1), "jdoe", "administrator", "SQL01.contoso.local"),
            Explicit(T0.AddMinutes(2), "jdoe", "administrator", "HV01.contoso.local"));
        var users = PivotBuilder.ByUser(events).ToDictionary(u => u.User, StringComparer.OrdinalIgnoreCase);

        Assert.Equal(2, users["jdoe"].UsedOthersCreds);
        Assert.Equal(0, users["jdoe"].CredsUsedByOthers);
        Assert.Equal(0, users["administrator"].UsedOthersCreds);
        Assert.Equal(2, users["administrator"].CredsUsedByOthers);
        Assert.True(users["jdoe"].SuspicionScore >= 6); // the hand-offs now raise the actor's score

        // An account seen only as the actor still gets a row.
        var actorOnly = PivotBuilder.ByUser(Normalize(Explicit(T0, "jdoe", "administrator", "SQL01.contoso.local"))).ToList();
        Assert.Contains(actorOnly, u => u.User == "jdoe" && u.UsedOthersCreds == 1 && !u.IsSystemAccount);
    }

    // 4 -----------------------------------------------------------------------------------------

    [Fact]
    public void AfterHoursFinding_NamesTheWeekdayAndWhy()
    {
        var events = Normalize(Zone(Sat.AddHours(-1)), Console(Sat.AddMinutes(1), 11, "0x51"));
        var f = Assert.Single(new SuspiciousSequenceAnalyzer(new AnalyzerOptions { UseHostTimeZones = true }).Run(events).Findings,
            x => x.RuleName.StartsWith("After-hours"));
        Assert.Contains("on Saturday 2026-09-12 (weekend; first at 10:52 UTC+08:00)", f.Description);

        var weekday = new DateTimeOffset(2026, 9, 15, 13, 30, 0, TimeSpan.Zero); // Tuesday 21:30 at UTC+8
        var late = Normalize(Zone(weekday.AddHours(-1)), Console(weekday, 2, "0x52"));
        var w = Assert.Single(new SuspiciousSequenceAnalyzer(new AnalyzerOptions { UseHostTimeZones = true }).Run(late).Findings,
            x => x.RuleName.StartsWith("After-hours"));
        Assert.Contains("on Tuesday 2026-09-15 (outside 07:00-19:00; first at 21:30 UTC+08:00)", w.Description);
    }

    // 5 -----------------------------------------------------------------------------------------

    [Fact]
    public void SystemFailureWhileLsaIsShuttingDown_IsNoise_OtherFailuresAreNot()
    {
        NormalizedEvent Fail(string user, string sid, string status) => _n.Normalize(Sec(4625, T0, Host,
            ("TargetUserSid", sid), ("TargetUserName", user), ("TargetDomainName", "NT AUTHORITY"), ("Status", status),
            ("SubStatus", "0x0"), ("LogonType", "5"), ("AuthenticationPackageName", "Negotiate"), ("IpAddress", "-")), Ctx)!;

        Assert.True(NoiseFilter.IsRoutineNoise(Fail("SYSTEM", "S-1-5-18", "0xc00000dc")));
        Assert.False(NoiseFilter.IsRoutineNoise(Fail("SYSTEM", "S-1-5-18", "0xc000006d")));
        Assert.False(NoiseFilter.IsRoutineNoise(Fail("jdoe", G, "0xc00000dc")));
        Assert.False(NoiseFilter.IsRoutineNoise(Fail("jdoe", "S-1-0-0", "0xc00000dc")));
    }

    [Fact]
    public void NullSidOnAFailedLogon_DoesNotMakeTheAccountASystemAccount()
    {
        var spray = Normalize(Failed(T0, Host, "jdoe", "203.0.113.9"), Failed(T0.AddSeconds(5), Host, "jdoe", "203.0.113.9"))
            .Select(e => { e.Sid = "S-1-0-0"; return e; }).ToList();
        Assert.All(spray, e => Assert.False(e.IsNoiseAccount));
        var u = Assert.Single(PivotBuilder.ByUser(spray));
        Assert.False(u.IsSystemAccount);
        Assert.True(u.SuspicionScore > 0);
        Assert.True(AccountClassifier.IsNoise(null, "S-1-0-0"));  // no name: still the anonymous / null subject
        Assert.True(AccountClassifier.IsNoise("-", "S-1-0-0"));
    }

    [Fact]
    public void ServiceInstallBySystem_ShowsSystemAsTheUser_WithoutAddingAUserRow()
    {
        var e = Normalize(ServiceInstall(T0, Host, "AsusSAIO", "\\SystemRoot\\System32\\drivers\\asussci2.sys", "S-1-5-18")).Single();
        Assert.Null(e.TargetUserName);
        Assert.Equal("SYSTEM", CsvExporter.EventColumns.Single(c => c.Header == "User").Value(e));
        Assert.Equal("NT AUTHORITY", CsvExporter.EventColumns.Single(c => c.Header == "Domain").Value(e));
        Assert.Empty(PivotBuilder.ByUser(new[] { e }));
    }

    [Fact]
    public void RemoteAccessSoftware_IsCountedSeparatelyFromRemoteExecution()
    {
        var events = Normalize(
            Console(T0, 2, "0x47a1c38"),
            ServiceInstall(T0.AddMinutes(5), Host, "Splashtop\u00c2\u00ae Remote Service SOS",
                "\"C:\\ProgramData\\Splashtop\\Temp\\unpacksos\\SRsvcSOSsvqp6TlZz0.exe\"", G));
        new SuspiciousSequenceAnalyzer().Run(events); // resolves the installer from the SID

        var user = Assert.Single(PivotBuilder.ByUser(events));
        Assert.Equal(0, user.RemoteExec);
        Assert.Equal(1, user.RemoteAccessTool);
        var host = Assert.Single(PivotBuilder.ByHost(events));
        Assert.Equal(0, host.RemoteExec);
        Assert.Equal(1, host.RemoteAccessTool);
    }

    // 6 -----------------------------------------------------------------------------------------

    [Fact]
    public void OutboundSessionWithoutAnAccount_GetsAnInferredUser_OnlyWhenTheHostHasOneInteractiveAccount()
    {
        var events = Normalize(
            Console(T0, 2, "0x47a1c38"),
            RdpClient(1024, T0.AddHours(1), "Server Name", "10.10.20.34"));
        var result = new SuspiciousSequenceAnalyzer().Run(events);
        var s = Assert.Single(result.Sessions);
        Assert.Null(s.User);
        Assert.Equal("jdoe", s.InferredUser);
        Assert.Contains("INFERRED", s.Evidence);
        var f = Assert.Single(result.Findings, x => x.RuleName == "Outbound RDP from this host");
        Assert.Contains("likely jdoe, the only interactive account on this host (inferred)", f.Description);
        Assert.Null(f.User); // a finding's User is evidence, never the inference

        var two = Normalize(
            Console(T0, 2, "0x47a1c38"),
            Console(T0.AddMinutes(5), 2, "0x47a1c99", "mlee"),
            RdpClient(1024, T0.AddHours(1), "Server Name", "10.10.20.34"));
        Assert.Null(Assert.Single(new SuspiciousSequenceAnalyzer().Run(two).Sessions).InferredUser);
    }

    // 7 -----------------------------------------------------------------------------------------

    [Fact]
    public void ConsoleBadPasswordsThenCachedLogon_AreFlagged_WithRemoteAccessSoftwareNoted()
    {
        var events = Normalize(
            Zone(Sat.AddDays(-1)),
            ServiceInstall(Sat.AddDays(-30), Host, "Splashtop\u00c2\u00ae Remote Service SOS",
                "\"C:\\ProgramData\\Splashtop\\Temp\\unpacksos\\SRsvcSOSpM.exe\"", G),
            BadPassword(Sat),
            BadPassword(Sat.AddSeconds(13)),
            BadPassword(Sat.AddSeconds(61)),
            Console(Sat.AddSeconds(65), 11, "0x51"),
            Console(Sat.AddSeconds(66), 7, "0x52"));

        var result = new SuspiciousSequenceAnalyzer(new AnalyzerOptions { UseHostTimeZones = true }).Run(events);
        var f = Assert.Single(result.Findings, x => x.RuleName == "Failed console logons followed by success");
        Assert.Equal(FindingSeverity.Low, f.Severity);
        Assert.Equal(3, f.Count);
        Assert.Contains("10:51-10:52 UTC+08:00 on Saturday 2026-09-12", f.Description);
        Assert.Contains("then success at 10:52 with cached domain credentials (type 11)", f.Description);
        Assert.Contains("Splashtop SOS", f.Description);
        Assert.DoesNotContain(result.Findings, x => x.RuleName == "Failed logons followed by success"); // network rule untouched

        var two = Normalize(BadPassword(Sat), BadPassword(Sat.AddSeconds(13)), Console(Sat.AddSeconds(20), 2, "0x53"));
        Assert.DoesNotContain(new SuspiciousSequenceAnalyzer().Run(two).Findings, x => x.RuleName.StartsWith("Failed console"));
    }

    // remote hosts ------------------------------------------------------------------------------

    [Fact]
    public void RemoteHostPivot_JoinsAnAddressWithItsName_AndCountsHandOffs()
    {
        var events = Normalize(
            Console(T0, 2, "0x47a1c38"),
            RdpClient(1024, T0.AddMinutes(1), "Server Name", "10.10.20.33"),
            RdpClient(1024, T0.AddMinutes(10), "Server Name", "10.10.20.33"),
            Explicit(T0.AddMinutes(10).AddSeconds(7), "jdoe", "administrator", "SQL01.contoso.local"),
            Explicit(T0.AddMinutes(40), "jdoe", "administrator", "nas-07"));
        var result = new SuspiciousSequenceAnalyzer().Run(events);
        var rows = PivotBuilder.ByRemoteHost(events, result.Sessions).ToList();

        Assert.Equal(2, rows.Count);
        var erp = rows[0];
        Assert.Equal("10.10.20.33", erp.RemoteHost);
        Assert.Equal("SQL01.contoso.local", erp.Name);
        Assert.Equal(2, erp.Connections);
        Assert.Equal(2, erp.Rdp);
        Assert.Equal(1, erp.ExplicitCreds);
        Assert.Equal("WS-0142", erp.FromHosts);
        Assert.Equal("CONTOSO\\jdoe", erp.Users);
        Assert.Equal("jdoe", erp.InferredUsers); // the first attempt recorded no account
        Assert.Equal("contoso\\administrator", erp.CredentialsUsed);
        Assert.False(erp.IsCollected);

        var ds = rows[1];
        Assert.Equal("nas-07", ds.RemoteHost);
        Assert.Equal(0, ds.Connections);
        Assert.Equal(1, ds.ExplicitCreds);
    }
}
