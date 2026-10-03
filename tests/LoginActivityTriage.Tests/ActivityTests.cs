using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>
/// The timeline "Activity" label (logon / logoff / session / power) and the power events imported
/// for it: boot, clean and unexpected shutdown, and who initiated a restart.
/// </summary>
public class ActivityTests
{
    private readonly EventNormalizer _n = new();
    private static readonly NormalizationContext Ctx = new();
    private const string Host = "WS-0142.contoso.local";

    private NormalizedEvent N(string xml) => _n.Normalize(xml, Ctx) ?? throw new Xunit.Sdk.XunitException("not normalised");

    private static string Shutdown1074(string type, string user) =>
        Event("User32", "System", 1074, T0, Host, new[]
        {
            ("param1", "C:\\WINDOWS\\system32\\shutdown.exe (WS-0142)"), ("param2", "WS-0142"),
            ("param3", "Other (Unplanned)"), ("param4", "0x0"), ("param5", type), ("param6", ""), ("param7", user),
        }, "S-1-5-21-9-9-9-4809");

    [Fact]
    public void LogonLogoffAndSessionEvents_CarryTheirActivity()
    {
        Assert.Equal(EventActivity.Logon, N(Logon(T0, Host, "jdoe", "CONTOSO", 11, "127.0.0.1", "0x51")).Activity);
        Assert.Equal(EventActivity.LogonFailed, N(Failed(T0, Host, "jdoe", "127.0.0.1", 2)).Activity);
        Assert.Equal(EventActivity.Logoff, N(Logoff(T0, Host, "jdoe", "0x51", 2)).Activity);
        Assert.Equal(EventActivity.Logoff, N(Sec(4647, T0, Host, ("TargetUserName", "jdoe"), ("TargetLogonId", "0x51"))).Activity);
        Assert.Equal(EventActivity.Logon, N(Lsm(21, T0, Host, "CONTOSO\\jdoe", "1", "本機")).Activity);
        Assert.Equal(EventActivity.Logoff, N(Lsm(23, T0, Host, "CONTOSO\\jdoe", "1", null)).Activity);
        Assert.Equal(EventActivity.Disconnect, N(Lsm(24, T0, Host, "CONTOSO\\jdoe", "1", null)).Activity);
        Assert.Equal(EventActivity.Reconnect, N(Lsm(25, T0, Host, "CONTOSO\\jdoe", "1", "10.10.20.9")).Activity);
        Assert.Null(N(Lsm(41, T0, Host, "CONTOSO\\jdoe", "1", null)).Activity); // LSM 41 = session arbitration
        Assert.Null(N(Sec(4648, T0, Host, ("SubjectUserName", "jdoe"), ("TargetUserName", "administrator"), ("TargetServerName", "SQL01"))).Activity);
    }

    [Fact]
    public void BootAndShutdownEvents_AreImported()
    {
        var boot = N(Positional("EventLog", "System", 6005, T0, Host, "", "", "", "", "", ""));
        Assert.Equal(EventActivity.Boot, boot.Activity);
        Assert.Equal("Event log service started (boot)", boot.EventType);
        Assert.Equal(EventActivity.Shutdown, N(Positional("EventLog", "System", 6006, T0, Host, "", "", "", "", "")).Activity);

        var crash = N(Positional("EventLog", "System", 6008, T0, Host, "上午 10:54:31", "2026/9/12", "", "", "", "", ""));
        Assert.Equal(EventActivity.UnexpectedShutdown, crash.Activity);
        Assert.Contains("上午 10:54:31 2026/9/12", crash.Details);

        var power = N(Event("Microsoft-Windows-Kernel-Power", "System", 41, T0, Host, new[] { ("BugcheckCode", "0"), ("PowerButtonTimestamp", "0") }));
        Assert.Equal(EventActivity.UnexpectedShutdown, power.Activity);
        Assert.Contains("no bugcheck", power.Details);

        Assert.Equal(EventActivity.Boot, N(Sec(4608, T0, Host)).Activity);
        Assert.Equal(EventActivity.Shutdown, N(Event("Microsoft-Windows-Eventlog", "Security", 1100, T0, Host, Array.Empty<(string, string)>())).Activity);
    }

    [Fact]
    public void RestartInitiatedByAUser_NamesTheUserAndProcess_InAnyLanguage()
    {
        var zh = N(Shutdown1074("重新啟動", "CONTOSO\\jdoe"));
        Assert.Equal(EventActivity.Restart, zh.Activity);
        Assert.Equal("jdoe", zh.TargetUserName);
        Assert.Equal("CONTOSO", zh.TargetDomain);
        Assert.Equal("C:\\WINDOWS\\system32\\shutdown.exe", zh.ProcessName);
        Assert.Contains("Other (Unplanned)", zh.Details);

        var off = N(Shutdown1074("power off", "NT AUTHORITY\\SYSTEM"));
        Assert.Equal(EventActivity.Shutdown, off.Activity);
        Assert.Null(off.TargetUserName);      // SYSTEM is not a user row ...
        Assert.Equal("SYSTEM", off.SubjectUserName); // ... but the actor is kept
        Assert.Equal(EventActivity.Shutdown, N(Shutdown1074("電源關閉", "CONTOSO\\jdoe")).Activity); // as logged on WS-0142
        Assert.Equal(EventActivity.ShutdownOrRestart, N(Shutdown1074("xyz", "CONTOSO\\jdoe")).Activity);
    }

    [Fact]
    public void PowerEvents_ReachTheTriageTimeline_AndAreNotNoise()
    {
        var events = new[]
        {
            N(Positional("EventLog", "System", 6005, T0, Host, "", "", "", "", "", "")),
            N(Event("Microsoft-Windows-Kernel-Power", "System", 41, T0, Host, new[] { ("BugcheckCode", "0") })),
            N(Shutdown1074("restart", "NT AUTHORITY\\SYSTEM")),
        };
        Assert.All(events, e => Assert.True(TriageTimeline.Include(e)));
        Assert.All(events, e => Assert.False(NoiseFilter.IsRoutineNoise(e)));
        Assert.Empty(PivotBuilder.ByUser(events)); // power events by SYSTEM add no account rows
        Assert.Empty(new SuspiciousSequenceAnalyzer().Run(events).Sessions);
    }
}
