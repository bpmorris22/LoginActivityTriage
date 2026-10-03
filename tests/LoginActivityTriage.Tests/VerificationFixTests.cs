using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Regression tests for the issues found when the WS-0142 results were checked against the
/// raw EVTX (2026-10-03): WinRM client errors shown as failures, outbound RDP counted as RDP to the
/// host, one logon counted four times, machine-account 4648 noise, merged RDP attempts, missing
/// user / target on outbound RDP, unflagged remote-access software, and time zones.
/// </summary>
public class VerificationFixTests
{
    private readonly EventNormalizer _n = new();
    private static readonly NormalizationContext Ctx = new();
    private const string Host = "WS-0142.contoso.local";

    private List<NormalizedEvent> Normalize(params string[] xml) =>
        ProcessEventFilter.Apply(xml.Select(x => _n.Normalize(x, Ctx)).Where(e => e is not null).Select(e => e!).ToList());

    private static string RdpClient(int id, DateTimeOffset t, string name, string value) =>
        Event("Microsoft-Windows-TerminalServices-ClientActiveXCore", "Microsoft-Windows-TerminalServices-RDPClient/Operational",
            id, t, Host, new[] { ("Name", name), ("Value", value), ("CustomLevel", "Info") });

    private static string Explicit(DateTimeOffset t, string subject, string targetUser, string server, string process = "C:\\Windows\\System32\\lsass.exe") =>
        Sec(4648, t, Host, ("SubjectUserSid", "S-1-5-21-9-9-9-4809"), ("SubjectUserName", subject), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", "0x47a1ede"), ("TargetUserName", targetUser), ("TargetDomainName", "contoso"),
            ("TargetServerName", server), ("TargetInfo", server), ("ProcessName", process), ("IpAddress", "-"));

    [Fact]
    public void WinRmClientError_IsNotAnAuthenticationFailure()
    {
        var e = _n.Normalize(Event(WinRm, "Microsoft-Windows-WinRM/Operational", 161, T0, Host,
            new[] { ("authFailureMessage", "The client cannot connect to the destination specified in the request.") }), Ctx);
        Assert.NotNull(e);
        Assert.False(e!.IsFailure);
        Assert.Null(e.Technique);
    }

    [Fact]
    public void ElevatedSplitTokenLogon_CountsOnce()
    {
        var events = Normalize(
            Sec(4624, T0, Host, ("TargetUserSid", "S-1-5-21-9-9-9-4809"), ("TargetUserName", "jdoe"), ("TargetDomainName", "CONTOSO"),
                ("TargetLogonId", "0x47a1c38"), ("TargetLinkedLogonId", "0x47a1ede"), ("LogonType", "2"), ("ElevatedToken", "%%1842"),
                ("IpAddress", "127.0.0.1"), ("AuthenticationPackageName", "Negotiate")),
            Sec(4624, T0, Host, ("TargetUserSid", "S-1-5-21-9-9-9-4809"), ("TargetUserName", "jdoe"), ("TargetDomainName", "CONTOSO"),
                ("TargetLogonId", "0x47a1ede"), ("TargetLinkedLogonId", "0x47a1c38"), ("LogonType", "2"), ("ElevatedToken", "%%1843"),
                ("IpAddress", "127.0.0.1"), ("AuthenticationPackageName", "Negotiate")),
            Sec(4672, T0, Host, ("SubjectUserSid", "S-1-5-21-9-9-9-4809"), ("SubjectUserName", "jdoe"), ("SubjectDomainName", "CONTOSO"),
                ("SubjectLogonId", "0x47a1c38"), ("PrivilegeList", "SeDebugPrivilege")),
            EventXml.Lsm(21, T0.AddSeconds(2), Host, "CONTOSO\\jdoe", "1", "本機"));

        Assert.Equal(1, events.Count(e => e.CountsAsLogonSuccess));
        var user = Assert.Single(PivotBuilder.ByUser(events));
        Assert.Equal(1, user.Successful);
        Assert.Equal(1, user.Privileged); // elevated 4624 + its 4672 = one privileged logon
        var host = Assert.Single(PivotBuilder.ByHost(events));
        Assert.Equal(1, host.Successful);
        Assert.Equal(1, host.Privileged);
    }

    [Fact]
    public void OutboundRdp_IsNotCountedAsRdpToTheHost()
    {
        var events = Normalize(
            RdpClient(1024, T0, "Server Name", "10.10.20.33"),
            RdpClient(1102, T0.AddSeconds(8), "ServerAddress", "10.10.20.33"));
        var host = Assert.Single(PivotBuilder.ByHost(events));
        Assert.Equal(0, host.Rdp);
        Assert.Equal(2, host.RdpOutbound);
    }

    [Fact]
    public void MachineAccountExplicitCredentialsToLocalhost_AreNoise_ButRemoteUseIsKept()
    {
        var umfd = _n.Normalize(Explicit(T0, "WS-0142$", "UMFD-0", "localhost", "C:\\Windows\\System32\\wininit.exe"), Ctx)!;
        var self = _n.Normalize(Explicit(T0, "WS-0142$", "WS-0142$", "ws-0142$", "C:\\Windows\\System32\\taskhostw.exe"), Ctx)!;
        var remote = _n.Normalize(Explicit(T0, "WS-0142$", "svc_backup", "NAS01.contoso.local"), Ctx)!;
        var human = _n.Normalize(Explicit(T0, "jdoe", "administrator", "localhost"), Ctx)!;
        Assert.True(NoiseFilter.IsRoutineNoise(umfd));
        Assert.True(NoiseFilter.IsRoutineNoise(self));
        Assert.False(NoiseFilter.IsRoutineNoise(remote));
        Assert.False(NoiseFilter.IsRoutineNoise(human));
    }

    [Fact]
    public void SystemAccounts_AreListedButNotRanked()
    {
        var events = new List<NormalizedEvent>
        {
            new() { EventId = 4648, TargetUserName = "UMFD-0", Hostname = Host, Timestamp = T0 },
            new() { EventId = 4648, TargetUserName = "administrator", Hostname = Host, Timestamp = T0 },
        };
        var pivots = PivotBuilder.ByUser(events).ToList();
        Assert.Equal(0, pivots.Single(p => p.User == "UMFD-0").SuspicionScore);
        Assert.True(pivots.Single(p => p.User == "UMFD-0").IsSystemAccount);
        Assert.Equal("administrator", pivots[0].User);
    }

    [Fact]
    public void OutboundRdp_EachAttemptIsASession_WithUserCredentialsAndTargetName()
    {
        var events = Normalize(
            RdpClient(1024, T0, "Server Name", "10.10.20.30"),
            RdpClient(1102, T0.AddSeconds(8), "ServerAddress", "10.10.20.30"),
            Explicit(T0.AddSeconds(7), "jdoe", "administrator", "HV01.contoso.local"),
            Explicit(T0.AddSeconds(7), "jdoe", "administrator", "HV01.contoso.local"),
            RdpClient(1024, T0.AddMinutes(4).AddSeconds(30), "Server Name", "10.10.20.30"),
            RdpClient(1102, T0.AddMinutes(4).AddSeconds(38), "ServerAddress", "10.10.20.30"),
            Explicit(T0.AddMinutes(4).AddSeconds(37), "jdoe", "administrator", "HV01.contoso.local"),
            RdpClient(1024, T0.AddMinutes(10), "Server Name", "10.10.20.32"));

        var result = new SuspiciousSequenceAnalyzer().Run(events);

        Assert.Equal(3, result.Sessions.Count);
        var first = result.Sessions[0];
        Assert.Equal("Outbound", first.Direction);
        Assert.Equal("jdoe", first.User);
        Assert.Equal("contoso\\administrator", first.CredentialsUsed);
        Assert.Equal("HV01.contoso.local", first.TargetHostName);
        Assert.Equal("10.10.20.30", first.TargetHost);
        Assert.Equal("High", first.Confidence);
        Assert.Null(result.Sessions[2].User); // no credential hand-off recorded for that attempt
        var f = Assert.Single(result.Findings, x => x.RuleName == "Outbound RDP from this host");
        Assert.Equal(3, f.Count);
        Assert.Equal("jdoe", f.User);
        Assert.Contains("10.10.20.30 (HV01.contoso.local) x2", f.Description);
        Assert.Contains("using contoso\\administrator", f.Description);
    }

    [Fact]
    public void SplashtopSosInstall_IsFlaggedHigh_WithInstallerResolvedFromSid()
    {
        var events = Normalize(
            Sec(4624, T0, Host, ("TargetUserSid", "S-1-5-21-9-9-9-4809"), ("TargetUserName", "jdoe"), ("TargetDomainName", "CONTOSO"),
                ("TargetLogonId", "0x47a1c38"), ("LogonType", "2"), ("IpAddress", "127.0.0.1"), ("AuthenticationPackageName", "Negotiate")),
            ServiceInstall(T0.AddMinutes(50), Host, "Splashtop\u00c2\u00ae Remote Service SOS",
                "\"C:\\ProgramData\\Splashtop\\Temp\\unpacksos\\SRsvcSOSsvqp6TlZz0.exe\"", "S-1-5-21-9-9-9-4809"));

        var svc = events.Single(e => e.EventId == 7045);
        Assert.Equal(RemoteTechnique.RemoteAccessTool, svc.Technique);
        Assert.Equal("Splashtop SOS (on-demand support)", svc.TechniqueDetail);

        var result = new SuspiciousSequenceAnalyzer().Run(events);
        Assert.Equal("jdoe", svc.TargetUserName); // resolved from the 4624's SID
        var f = Assert.Single(result.Findings, x => x.RuleName == "Remote access software installed");
        Assert.Equal(FindingSeverity.High, f.Severity);
        Assert.Equal("T1219", f.Mitre);
        Assert.Contains("CONTOSO\\jdoe", f.Description);
        Assert.Empty(result.Sessions); // a RAT install is not mistaken for a PsExec / remote service session
    }

    [Theory]
    [InlineData("C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe", "AnyDesk")]
    [InlineData("C:\\Program Files (x86)\\TeamViewer\\TeamViewer.exe", "TeamViewer")]
    [InlineData("C:\\Program Files (x86)\\ScreenConnect Client (abc)\\ScreenConnect.ClientService.exe", "ConnectWise ScreenConnect")]
    public void RemoteAccessToolProcess_IsRecognised(string image, string tool)
    {
        var m = RemoteExecPatterns.ClassifyProcess(image, "C:\\Windows\\explorer.exe", $"\"{image}\"");
        Assert.NotNull(m);
        Assert.Equal(RemoteTechnique.RemoteAccessTool, m!.Value.Technique);
        Assert.Equal(tool, m.Value.Variant);
    }

    [Fact]
    public void Event6013_GivesTheHostOffset_AndAfterHoursUsesIt()
    {
        // 6013: positional data, last item "<bias minutes> <localised zone name>".
        var tz = Positional("EventLog", "System", 6013, T0, Host, "", "", "", "", "176706", "60", "-480 台北標準時間");
        var e = _n.Normalize(tz, Ctx);
        Assert.NotNull(e);
        Assert.Equal(480, e!.UtcOffsetMinutes);
        Assert.StartsWith("UTC+08:00", e.Details);

        // 23:30Z Tuesday = 07:30 Wednesday at UTC+8: inside business hours on the host.
        var logon = new NormalizedEvent
        {
            EventId = 4624, LogonType = 2, TargetUserName = "jdoe", Hostname = Host,
            Timestamp = new DateTimeOffset(2026, 6, 16, 23, 30, 0, TimeSpan.Zero), IsSuccess = true,
        };
        var events = new List<NormalizedEvent> { e, logon };
        Assert.Contains(new SuspiciousSequenceAnalyzer().Run(events).Findings, f => f.RuleName.StartsWith("After-hours"));
        var auto = new SuspiciousSequenceAnalyzer(new AnalyzerOptions { UseHostTimeZones = true }).Run(events);
        Assert.DoesNotContain(auto.Findings, f => f.RuleName.StartsWith("After-hours"));
        Assert.Equal("UTC+08:00", auto.HostZones["WS-0142"].Id);
        Assert.False(TriageTimeline.Include(e));
    }

    [Theory]
    [InlineData("UTC+08:00", 480)]
    [InlineData("+8", 480)]
    [InlineData("UTC-05:30", -330)]
    [InlineData("utc", 0)]
    public void TimeZoneParse_AcceptsOffsets(string text, int minutes) =>
        Assert.Equal(TimeSpan.FromMinutes(minutes), TimeZoneUtil.Parse(text).BaseUtcOffset);

    [Theory]
    [InlineData("Microsoft-Windows-AAD%254Operational.evtx", "Microsoft-Windows-AAD/Operational")]
    [InlineData("Microsoft-Windows-PowerShell%254Operational.evtx", "PowerShell-Operational")]
    public void VelociraptorEncodedChannelNames_AreDecoded(string file, string expected) =>
        Assert.Equal(expected, EvtxImporter.InferLogSource(file));
}
