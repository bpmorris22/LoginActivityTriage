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
}
