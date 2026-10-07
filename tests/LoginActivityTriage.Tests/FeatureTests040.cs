using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Security.Cryptography;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>0.4.0 features: public-source rules, group removals and renames, cifs/ and RPCSS/ hand-offs, overnight hours, evidence hashes.</summary>
public class FeatureTests040
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-08-24T08:00:00Z");
    private const string Public = "203.0.113.45";
    private readonly EventNormalizer _n = new();

    private List<NormalizedEvent> Normalize(params string[] xml) =>
        ProcessEventFilter.Apply(xml.Select(x => _n.Normalize(x, new NormalizationContext())).Where(e => e is not null).Select(e => e!).ToList());

    private static string Rcm1149(DateTimeOffset t, string host, string user, string domain, string ip) =>
        Event(Rcm, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149, t, host,
            new[] { ("Param1", user), ("Param2", domain), ("Param3", ip) });

    private static string CoreTs(int id, DateTimeOffset t, string host, string ip) =>
        Event(EventXml.CoreTs, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", id, t, host,
            new[] { ("ClientIP", ip + ":50123"), ("ConnType", "TCP") });

    private static string GroupChange(int id, DateTimeOffset t, string host, string sid, string group = "Administrators") =>
        Sec(id, t, host, ("MemberName", "-"), ("MemberSid", sid), ("TargetUserName", group), ("TargetDomainName", "Builtin"),
            ("TargetSid", "S-1-5-32-544"), ("SubjectUserSid", "S-1-5-21-9-8-7-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", host));

    // ---------------------------------------------------------------- public sources

    [Fact]
    public void NetworkLogonFromAPublicAddress_IsAHighFinding()
    {
        var events = Normalize(Logon(T0, "FS01", "jdoe", "CONTOSO", 3, Public, "0x111", "NTLM", "ATTACKER"),
                               Logon(T0.AddMinutes(1), "FS01", "jdoe", "CONTOSO", 3, "10.10.20.5", "0x112"));
        var r = new SuspiciousSequenceAnalyzer().Run(events);
        var f = Assert.Single(r.Findings, x => x.RuleName == "Network logon from external address");
        Assert.Equal(FindingSeverity.High, f.Severity);
        Assert.Equal(Public, f.SourceIp);
        Assert.Equal(1, f.Count);                                            // the private-address logon is not counted
        Assert.Contains("type 3", f.Description);
    }

    [Fact]
    public void RdpNlaFromAPublicAddress_WithoutASecurityLogon_IsHigh_AndNotDuplicatedWhenTheLogonExists()
    {
        var alone = new SuspiciousSequenceAnalyzer().Run(Normalize(Rcm1149(T0, "TS01", "jdoe", "CONTOSO", Public)));
        var f = Assert.Single(alone.Findings, x => x.RuleName == "RDP authentication from external address");
        Assert.Equal(FindingSeverity.High, f.Severity);
        Assert.Equal("jdoe", f.User);
        Assert.DoesNotContain(alone.Findings, x => x.RuleName == "RDP logon from external address");

        var withLogon = new SuspiciousSequenceAnalyzer().Run(Normalize(
            Rcm1149(T0, "TS01", "jdoe", "CONTOSO", Public),
            Logon(T0.AddSeconds(5), "TS01", "jdoe", "CONTOSO", 10, Public, "0x222", "Negotiate")));
        Assert.Single(withLogon.Findings, x => x.RuleName == "RDP logon from external address");
        Assert.DoesNotContain(withLogon.Findings, x => x.RuleName == "RDP authentication from external address");
    }

    [Fact]
    public void BareRdpConnectionsFromPublicAddresses_AreOneMediumFindingPerHost()
    {
        var events = Normalize(
            CoreTs(131, T0, "TS01", "198.51.100.7"), CoreTs(131, T0.AddMinutes(1), "TS01", "198.51.100.8"),
            CoreTs(140, T0.AddMinutes(2), "TS01", "198.51.100.8"), CoreTs(131, T0.AddMinutes(3), "TS01", "10.10.20.9"));
        var r = new SuspiciousSequenceAnalyzer().Run(events);
        var f = Assert.Single(r.Findings, x => x.RuleName == "RDP reachable from the internet");
        Assert.Equal(FindingSeverity.Medium, f.Severity);
        Assert.Equal(3, f.Count);                                            // the private address is not counted
        Assert.Contains("2 public address(es)", f.Description);
        Assert.Contains("1 with bad credentials", f.Description);
        Assert.Equal("131,140", f.RelatedEventIds);
    }

    // ---------------------------------------------------------------- group removals / renames

    [Fact]
    public void MemberRemovedShortlyAfterBeingAdded_IsTheAddThenRemovePattern()
    {
        const string sid = "S-1-5-21-1-2-3-1105";
        var events = Normalize(
            Logon(T0, "SRV01", "jdoe", "SRV01", 2, null, "0x77"),           // names the SID
            GroupChange(4732, T0.AddMinutes(5), "SRV01", sid),
            GroupChange(4733, T0.AddMinutes(50), "SRV01", sid));
        var r = new SuspiciousSequenceAnalyzer().Run(events);

        Assert.Single(r.Findings, x => x.RuleName == "Member added to privileged group");
        var f = Assert.Single(r.Findings, x => x.RuleName == "Privileged group membership added then removed");
        Assert.Equal(FindingSeverity.High, f.Severity);
        Assert.StartsWith($"jdoe ({sid}) removed from Administrators on SRV01", f.Description);
        Assert.Contains("45 min after being added", f.Description);
        Assert.Equal("4732,4733", f.RelatedEventIds);
        Assert.Equal(2, PivotBuilder.ByUser(events).Single(u => u.User == "jdoe").GroupChanges);
    }

    [Fact]
    public void MemberRemovedWithoutARecentAdd_IsMedium()
    {
        var r = new SuspiciousSequenceAnalyzer().Run(Normalize(GroupChange(4729, T0, "DC01", "S-1-5-21-1-2-3-1105", "Domain Admins")));
        var f = Assert.Single(r.Findings, x => x.RuleName == "Member removed from privileged group");
        Assert.Equal(FindingSeverity.Medium, f.Severity);
        Assert.Equal("4729", f.RelatedEventIds);
    }

    [Fact]
    public void ARenamedAccount_IsNamedByItsCurrentName()
    {
        const string sid = "S-1-5-21-9-8-7-1003";
        var events = Normalize(
            Sec(4720, T0, "SRV01", ("TargetUserName", "tmp1"), ("TargetDomainName", "SRV01"), ("TargetSid", sid),
                ("SubjectUserSid", "S-1-5-21-9-8-7-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "SRV01")),
            Sec(4781, T0.AddMinutes(1), "SRV01", ("OldTargetUserName", "tmp1"), ("NewTargetUserName", "svc_backup"), ("TargetDomainName", "SRV01"),
                ("TargetSid", sid), ("SubjectUserSid", "S-1-5-21-9-8-7-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "SRV01")),
            GroupChange(4732, T0.AddMinutes(2), "SRV01", sid));
        var r = new SuspiciousSequenceAnalyzer().Run(events);

        var renamed = events.Single(e => e.EventId == 4781);
        Assert.Equal("svc_backup", renamed.TargetUserName);
        Assert.Contains("Renamed from tmp1", renamed.Details);
        Assert.Equal("svc_backup", events.Single(e => e.EventId == 4732).TargetUserName);
        var f = Assert.Single(r.Findings, x => x.RuleName == "New account added to privileged group");   // same SID as the 4720
        Assert.StartsWith($"svc_backup ({sid}) added to Administrators", f.Description);
    }

    // ---------------------------------------------------------------- 4648 SPN classes

    [Fact]
    public void ExplicitCredentialsForACifsSpn_AreAnOutboundSmbSession()
    {
        var e = _n.Normalize(Sec(4648, T0, "WS01", ("SubjectUserSid", "S-1-5-21-1-2-3-1105"), ("SubjectUserName", "jdoe"), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", "0x3e9"), ("TargetUserName", "administrator"), ("TargetDomainName", "CONTOSO"), ("TargetServerName", "FS01.contoso.local"),
            ("TargetInfo", "cifs/FS01.contoso.local"), ("ProcessName", "C:\\Windows\\System32\\net.exe"), ("IpAddress", "-")), new NormalizationContext())!;
        Assert.Equal(RemoteTechnique.Smb, e.Technique);
        Assert.True(e.IsOutbound);

        var r = new SuspiciousSequenceAnalyzer().Run(new List<NormalizedEvent> { e });
        var s = Assert.Single(r.Sessions);
        Assert.Equal("Outbound", s.Direction);
        Assert.Equal(RemoteTechnique.Smb, s.Technique);
        Assert.Equal("FS01.contoso.local", s.TargetHost);
        Assert.Equal("jdoe", s.User);
        Assert.Equal("CONTOSO\\administrator", s.CredentialsUsed);
        Assert.Single(r.Findings, f => f.RuleName == "Outbound SMB with explicit credentials from this host");
    }

    [Fact]
    public void ExplicitCredentialsForAnRpcssSpn_AreOutboundWmi()
    {
        var e = _n.Normalize(Sec(4648, T0, "WS01", ("SubjectUserSid", "S-1-5-21-1-2-3-1105"), ("SubjectUserName", "jdoe"), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", "0x3e9"), ("TargetUserName", "jdoe"), ("TargetDomainName", "CONTOSO"), ("TargetServerName", "SQL01.contoso.local"),
            ("TargetInfo", "RPCSS/SQL01.contoso.local"), ("ProcessName", "C:\\Windows\\System32\\wbem\\wmic.exe"), ("IpAddress", "-")), new NormalizationContext())!;
        Assert.Equal(RemoteTechnique.Wmi, e.Technique);
        Assert.True(e.IsOutbound);
    }

    // ---------------------------------------------------------------- overnight business hours

    [Fact]
    public void BusinessHoursAcrossMidnight_FlagTheDaytime()
    {
        var night = Logon(DateTimeOffset.Parse("2026-08-25T23:30:00Z"), "WS01", "jdoe", "CONTOSO", 2, null, "0x1");   // Tuesday 23:30 UTC
        var day = Logon(DateTimeOffset.Parse("2026-08-25T10:00:00Z"), "WS01", "jdoe", "CONTOSO", 2, null, "0x2");     // Tuesday 10:00 UTC
        var o = new AnalyzerOptions { TimeZone = TimeZoneInfo.Utc, BusinessStartHour = 22, BusinessEndHour = 6 };
        var r = new SuspiciousSequenceAnalyzer(o).Run(Normalize(night, day));
        var f = Assert.Single(r.Findings, x => x.RuleName == "After-hours interactive / RDP logon");
        Assert.Equal(DateTimeOffset.Parse("2026-08-25T10:00:00Z"), f.Timestamp);                                   // the daytime logon, not the night shift
        Assert.Contains("outside 22:00-06:00", f.Description);
    }

    // ---------------------------------------------------------------- evidence hashes

    [Fact]
    public void FilesCsv_CarriesTheSha256AndSizeOfEachSourceLog()
    {
        var dir = Path.Combine(Path.GetTempPath(), "lat-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            long first;
            using (var r = new EventLogReader(new EventLogQuery("Application", PathType.LogName)))
            using (var rec = r.ReadEvent()) { Assert.NotNull(rec); first = rec!.RecordId ?? 0; }
            var evtx = Path.Combine(dir, "Application.evtx");
            EventLogSession.GlobalSession.ExportLog("Application", PathType.LogName,
                $"*[System[(EventRecordID>={first} and EventRecordID<{first + 20})]]", evtx);

            var summary = new EvtxImporter().Import(evtx, _ => { });
            var f = Assert.Single(summary.Files);
            Assert.False(f.Failed, f.Error);
            Assert.Equal(new FileInfo(evtx).Length, f.SizeBytes);
            using var fs = File.OpenRead(evtx);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant(), f.Sha256);

            var off = new EvtxImporter().Import(evtx, _ => { }, options: new ImportOptions { HashFiles = false });
            Assert.Null(off.Files[0].Sha256);
            Assert.Null(off.Files[0].SizeBytes);
        }
        finally { Directory.Delete(dir, recursive: true); }
    }
}
