using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Models;
using Xunit;

namespace LoginActivityTriage.Tests;

public class AnalyticsTests
{
    private static NormalizedEvent Ev(DateTimeOffset ts, int id, string user, string? ip, string host,
        bool success, bool failure) => new()
    {
        Timestamp = ts,
        EventId = id,
        TargetUserName = user,
        SourceIp = ip,
        Hostname = host,
        IsSuccess = success,
        IsFailure = failure,
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
            Ev(t0.AddMinutes(3),   4624, "admin", "10.0.0.5", "HOST1", true,  false),
        };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.Contains(findings, f => f.RuleName == "Failed logons followed by success");
    }

    [Fact]
    public void AfterHoursLogon_IsDetected()
    {
        var night = new DateTimeOffset(2026, 6, 20, 3, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent>
        {
            Ev(night, 4624, "jdoe", "10.0.0.9", "HOST1", true, false),
        };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.Contains(findings, f => f.RuleName == "After-hours logon");
    }

    [Fact]
    public void NormalBusinessHours_NoAfterHoursFinding()
    {
        var noon = new DateTimeOffset(2026, 6, 20, 12, 0, 0, TimeSpan.Zero);
        var events = new List<NormalizedEvent> { Ev(noon, 4624, "jdoe", "10.0.0.9", "HOST1", true, false) };

        var findings = new SuspiciousSequenceAnalyzer().Analyze(events);

        Assert.DoesNotContain(findings, f => f.RuleName == "After-hours logon");
    }
}
