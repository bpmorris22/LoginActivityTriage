using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Group-member events for a LOCAL account (4732 on a member server) log MemberName "-" and only
/// the MemberSid. 0.3.1 and earlier showed that SID as the user of the event and of the "added to
/// privileged group" finding even when 4720 / 4624 named the account (0.3.2).
/// </summary>
public class SidResolutionTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.Parse("2026-08-24T08:56:27Z");
    private const string LocalSid = "S-1-5-21-9-8-7-1003";
    private readonly EventNormalizer _n = new();

    private List<NormalizedEvent> Normalize(params string[] xml) =>
        ProcessEventFilter.Apply(xml.Select(x => _n.Normalize(x, new NormalizationContext())).Where(e => e is not null).Select(e => e!).ToList());

    private static string Created(string user, string sid) =>
        Sec(4720, T0, "SRV01", ("TargetUserName", user), ("TargetDomainName", "SRV01"), ("TargetSid", sid),
            ("SubjectUserSid", "S-1-5-21-9-8-7-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "SRV01"));

    private static string AddedToAdministrators(string sid, int seconds = 15) =>
        Sec(4732, T0.AddSeconds(seconds), "SRV01", ("MemberName", "-"), ("MemberSid", sid),
            ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"), ("TargetSid", "S-1-5-32-544"),
            ("SubjectUserSid", "S-1-5-21-9-8-7-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "SRV01"));

    [Fact]
    public void LocalMemberSid_IsNamedByTheAccountCreation()
    {
        var events = Normalize(Created("svc_report", LocalSid), AddedToAdministrators(LocalSid));
        Assert.Equal(LocalSid, events[1].TargetUserName);   // what the 4732 itself carries
        var result = new SuspiciousSequenceAnalyzer().Run(events);

        Assert.Equal("svc_report", events[1].TargetUserName);
        Assert.Equal("SRV01", events[1].TargetDomain);      // the account's domain, not the group's "Builtin"
        Assert.Equal(LocalSid, events[1].Sid);
        Assert.Equal("Administrators", events[1].GroupName);
        var f = Assert.Single(result.Findings, x => x.RuleName == "New account added to privileged group");
        Assert.Equal(FindingSeverity.Critical, f.Severity);
        Assert.Equal("svc_report", f.User);
        Assert.StartsWith($"svc_report ({LocalSid}) added to Administrators", f.Description);
    }

    [Fact]
    public void LocalMemberSid_IsNamedByALogon()
    {
        // Logon() logs TargetUserSid S-1-5-21-1-2-3-1105.
        var events = Normalize(Logon(T0, "SRV01", "jdoe", "SRV01", 3, "10.0.0.5", "0x77"), AddedToAdministrators("S-1-5-21-1-2-3-1105"));
        var result = new SuspiciousSequenceAnalyzer().Run(events);
        Assert.Equal("jdoe", events.Single(e => e.EventId == 4732).TargetUserName);
        var f = Assert.Single(result.Findings, x => x.RuleName == "Member added to privileged group");
        Assert.Equal("jdoe", f.User);
    }

    [Fact]
    public void UnnamedMemberSid_StaysTheUser_AndIsNotRepeated()
    {
        var events = Normalize(AddedToAdministrators(LocalSid));
        var result = new SuspiciousSequenceAnalyzer().Run(events);
        Assert.Equal(LocalSid, events[0].TargetUserName);
        var f = Assert.Single(result.Findings, x => x.RuleName == "Member added to privileged group");
        Assert.StartsWith($"{LocalSid} added to Administrators", f.Description);
    }

    [Fact]
    public void UserPivot_CarriesTheSid_ButNotTheNullSidOfFailedLogons()
    {
        var events = Normalize(
            Created("svc_report", LocalSid), AddedToAdministrators(LocalSid),
            Sec(4625, T0.AddMinutes(5), "SRV01", ("SubjectUserSid", "S-1-0-0"), ("TargetUserSid", "S-1-0-0"),
                ("TargetUserName", "guess"), ("TargetDomainName", "SRV01"), ("LogonType", "3"), ("IpAddress", "10.0.0.9"),
                ("Status", "0xc000006d"), ("SubStatus", "0xc0000064")));
        new SuspiciousSequenceAnalyzer().Run(events);
        var users = PivotBuilder.ByUser(events).ToList();

        var svc_report = Assert.Single(users, u => u.User == "svc_report");   // the 4720 and the resolved 4732 are one row
        Assert.Equal(LocalSid, svc_report.Sid);
        Assert.Equal(1, svc_report.GroupChanges);
        Assert.Null(Assert.Single(users, u => u.User == "guess").Sid);
        Assert.DoesNotContain(users, u => u.User == LocalSid);
    }

    /// <summary>
    /// 0.3.2 regression (review 2026-10-07): once a local member was named, the group rule matched a
    /// 4720 on ANOTHER host by bare name alone, so two different local accounts called "backup" on
    /// two hosts produced a false Critical "New account added". With both SIDs present the SIDs decide.
    /// </summary>
    [Fact]
    public void GroupRule_DoesNotMatchACreationOnAnotherHostByBareNameAlone()
    {
        var sidA = "S-1-5-21-1-1-1-1005";                                   // HOSTA\backup
        var sidB = "S-1-5-21-1-2-3-1105";                                   // HOSTB\backup (the SID Logon() logs)
        var created = Sec(4720, T0, "HOSTA", ("TargetUserName", "backup"), ("TargetDomainName", "HOSTA"), ("TargetSid", sidA),
            ("SubjectUserSid", "S-1-5-21-1-1-1-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "HOSTA"));
        var logonB = Logon(T0.AddHours(1), "HOSTB", "backup", "HOSTB", 2, null, "0x777");
        var addedB = Sec(4732, T0.AddHours(2), "HOSTB", ("MemberName", "-"), ("MemberSid", sidB),
            ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"), ("TargetSid", "S-1-5-32-544"),
            ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "HOSTB"));

        var events = Normalize(created, logonB, addedB);
        var result = new SuspiciousSequenceAnalyzer().Run(events);

        Assert.Equal("backup", events.Single(e => e.EventId == 4732).TargetUserName);   // still named by HOSTB's own logon
        var f = Assert.Single(result.Findings, x => x.RuleName.Contains("privileged group"));
        Assert.Equal("Member added to privileged group", f.RuleName);
        Assert.Equal(FindingSeverity.High, f.Severity);
        Assert.Equal("4732", f.RelatedEventIds);
    }

    /// <summary>
    /// Review 2026-10-07: a RunAs / JEA remoting endpoint logs 4103 under the RunAs account's SID while
    /// ContextInfo names the connected user. The resolver must not teach that SID the connected user's
    /// name, or every nameless event under it (a 7045 the RunAs account installed) is misattributed.
    /// </summary>
    [Fact]
    public void SidResolver_DoesNotNameARunAsSidAfterTheConnectedUser()
    {
        var runAsSid = "S-1-5-21-9-8-7-2001";                              // CONTOSO\svc_jea
        var ctx = "Host Name = ServerRemoteHost\r\nHost Application = C:\\Windows\\system32\\wsmprovhost.exe -Embedding\r\n" +
                  "User = CONTOSO\\svc_jea\r\nConnected User = CONTOSO\\jdoe\r\nCommand Name = Get-Service";
        var ps4103 = Event(PsOperational, "Microsoft-Windows-PowerShell/Operational", 4103, T0, "SRV01",
            new[] { ("ContextInfo", ctx), ("Payload", "CommandInvocation(Get-Service)") }, runAsSid);
        var svc = ServiceInstall(T0.AddMinutes(1), "SRV01", "UpdaterSvc", "C:\\ProgramData\\upd\\u.exe", runAsSid);

        var events = Normalize(ps4103, svc);
        new SuspiciousSequenceAnalyzer().Run(events);

        var e4103 = events.Single(e => e.EventId == 4103);
        Assert.Equal("jdoe", e4103.TargetUserName);                         // the connected user stays the subject
        Assert.Null(e4103.Sid);                                             // the RunAs SID is not the subject's
        Assert.Contains("svc_jea", e4103.Details);
        var e7045 = events.Single(e => e.EventId == 7045);
        Assert.NotEqual("jdoe", e7045.TargetUserName);
        Assert.Equal(runAsSid, e7045.Sid);
    }

    /// <summary>Names still come from Security events that pair the account's own SID with its name (4624 here).</summary>
    [Fact]
    public void SidResolver_StillNamesAServiceInstallFromASecurityLogon()
    {
        var events = Normalize(
            Logon(T0, "SRV01", "jdoe", "CONTOSO", 10, "10.0.0.5", "0x77"),  // TargetUserSid S-1-5-21-1-2-3-1105
            ServiceInstall(T0.AddMinutes(1), "SRV01", "UpdaterSvc", "C:\\ProgramData\\upd\\u.exe", "S-1-5-21-1-2-3-1105"));
        new SuspiciousSequenceAnalyzer().Run(events);
        Assert.Equal("jdoe", events.Single(e => e.EventId == 7045).TargetUserName);
    }
}
