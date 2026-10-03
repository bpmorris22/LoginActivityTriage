using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Models;
using Xunit;

namespace LoginActivityTriage.Tests;

public class AnalyticsTests
{
    private static NormalizedEvent Ev(DateTimeOffset ts, int id, string user, string? ip, string host,
        bool success, bool failure, int? logonType = null) => new()
    {
        Timestamp = ts,
        EventId = id,
        TargetUserName = user,
        SourceIp = ip,
        Hostname = host,
        IsSuccess = success,
        IsFailure = failure,
        LogonType = logonType,
    };

    [Fact]
    public void FailedThenSuccess_IsDetected()
    {
        var t0 = new DateTimeOffset(2026, 6, 20, 10, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent>
        {
            Ev(t0,                 4625, "admin", "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(1),   4625, "admin", "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(2),   4625, "admin", "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(3),   4624, "admin", "10.0.0.5", "HOST1", true,  false, 3),
        };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.Contains(findings, f => f.RuleName == "Failed logons followed by success");
    }

    [Fact]
    public void FailedThenSuccess_DifferentUsers_NotCorrelated()
    {
        var t0 = new DateTimeOffset(2026, 6, 20, 10, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent>
        {
            Ev(t0,               4625, "bob",   "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(1), 4625, "bob",   "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(2), 4625, "bob",   "10.0.0.5", "HOST1", false, true),
            Ev(t0.AddMinutes(3), 4624, "alice", "10.0.0.5", "HOST1", true,  false, 3),
        };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.DoesNotContain(findings, f => f.RuleName == "Failed logons followed by success");
    }

    [Fact]
    public void AfterHoursLogon_IsDetected_AndAggregatedPerDay()
    {
        var night = new DateTimeOffset(2026, 6, 17, 3, 0, 0, TimeSpan.Zero); // Wednesday
        var events = new List<NormalizedEvent>
        {
            Ev(night, 4624, "jdoe", "10.0.0.9", "HOST1", true, false, 10),
            Ev(night.AddMinutes(20), 4624, "jdoe", "10.0.0.9", "HOST1", true, false, 10),
        };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        var f = Assert.Single(findings, f => f.RuleName == "After-hours interactive / RDP logon");
        Assert.Equal(2, f.Count);
    }

    [Fact]
    public void AfterHours_UsesConfiguredTimeZone()
    {
        // 23:30 UTC on a Tuesday is 08:30 Wednesday in Tokyo (UTC+9): inside business hours there.
        var t = new DateTimeOffset(2026, 6, 16, 23, 30, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent> { Ev(t, 4624, "jdoe", "10.0.0.9", "HOST1", true, false, 2) };
        var tokyo = TimeZoneInfo.FindSystemTimeZoneById("Tokyo Standard Time");

        var utcFindings = new SuspiciousSequenceAnalyzer().Analyze(events);
        var tokyoFindings = new SuspiciousSequenceAnalyzer(new AnalyzerOptions { TimeZone = tokyo }).Analyze(events);

        Assert.Contains(utcFindings, f => f.RuleName.StartsWith("After-hours"));
        Assert.DoesNotContain(tokyoFindings, f => f.RuleName.StartsWith("After-hours"));
    }

    [Fact]
    public void NormalBusinessHours_NoAfterHoursFinding()
    {
        var noon = new DateTimeOffset(2026, 6, 17, 12, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent> { Ev(noon, 4624, "jdoe", "10.0.0.9", "HOST1", true, false, 2) };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.DoesNotContain(findings, f => f.RuleName.StartsWith("After-hours"));
    }

    [Fact]
    public void NetworkLogon_IsNotAfterHoursNoise()
    {
        var night = new DateTimeOffset(2026, 6, 17, 3, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent> { Ev(night, 4624, "jdoe", "10.0.0.9", "HOST1", true, false, 3) };

        Assert.DoesNotContain(new SuspiciousSequenceAnalyzer().Analyze(events), f => f.RuleName.StartsWith("After-hours"));
    }

    [Fact]
    public void PasswordSpray_IsDetected()
    {
        var t0 = new DateTimeOffset(2026, 6, 20, 10, 0, 0, TimeSpan.Zero);
        var events = Enumerable.Range(0, 10)
            .Select(i => Ev(t0.AddSeconds(i * 20), 4625, $"user{i}", "203.0.113.50", "DC01", false, true))
            .ToList();

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.Contains(findings, f => f.RuleName == "Password spray" && f.SourceIp == "203.0.113.50");
    }

    [Fact]
    public void MachineAccountsAndSystem_AreNotPrivilegedNoise()
    {
        var sys = new NormalizedEvent { EventId = 4672, TargetUserName = "SYSTEM", Sid = "S-1-5-18" };
        var machine = new NormalizedEvent { EventId = 4624, TargetUserName = "WKS01$", ElevatedToken = true };
        var dwm = new NormalizedEvent { EventId = 4624, TargetUserName = "DWM-3", ElevatedToken = true };
        var admin = new NormalizedEvent { EventId = 4672, TargetUserName = "jdoe", Sid = "S-1-5-21-1-2-3-1105" };

        Assert.False(sys.IsPrivileged);
        Assert.False(machine.IsPrivileged);
        Assert.False(dwm.IsPrivileged);
        Assert.True(admin.IsPrivileged);
    }

    [Fact]
    public void ProcessEventFilter_KeepsOnlyProcessesInRemoteLogonSessions()
    {
        var t0 = new DateTimeOffset(2026, 6, 20, 10, 0, 0, TimeSpan.Zero);
        var logon = new NormalizedEvent { EventId = 4624, LogonType = 3, LogonId = "0xabc", Hostname = "SRV1", TargetUserName = "jdoe", Timestamp = t0 };
        var inSession = new NormalizedEvent { EventId = 4688, LogonId = "0xabc", Hostname = "SRV1", KeepOnlyIfLinked = true, Timestamp = t0 };
        var local = new NormalizedEvent { EventId = 4688, LogonId = "0x999", Hostname = "SRV1", KeepOnlyIfLinked = true, Timestamp = t0 };
        var otherHost = new NormalizedEvent { EventId = 4688, LogonId = "0xabc", Hostname = "SRV2", KeepOnlyIfLinked = true, Timestamp = t0 };

        var kept = ProcessEventFilter.Apply(new[] { logon, inSession, local, otherHost });

        Assert.Contains(inSession, kept);
        Assert.DoesNotContain(local, kept);
        Assert.DoesNotContain(otherHost, kept);
        Assert.False(inSession.KeepOnlyIfLinked);
    }
}
