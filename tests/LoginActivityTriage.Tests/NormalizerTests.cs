using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Parsing;
using Xunit;

namespace LoginActivityTriage.Tests;

public class NormalizerTests
{
    private readonly EventNormalizer _normalizer = new();
    private static readonly NormalizationContext Ctx = new() { LogSource = "Security" };

    [Fact]
    public void Logon4624_ExtractsCoreFields()
    {
        var e = _normalizer.Normalize(SampleEvents.Logon4624, Ctx);

        Assert.NotNull(e);
        Assert.Equal(4624, e!.EventId);
        Assert.Equal("Successful logon", e.EventType);
        Assert.Equal("jdoe", e.TargetUserName);
        Assert.Equal("CONTOSO", e.TargetDomain);
        Assert.Equal("10.20.30.40", e.SourceIp);
        Assert.Equal(10, e.LogonType);
        Assert.Equal("RemoteInteractive / RDP", e.LogonTypeDescription);
        Assert.Equal("Negotiate", e.AuthenticationPackage);
        Assert.True(e.IsSuccess);
        Assert.True(e.IsRdp);
        Assert.Equal(true, e.ElevatedToken);
        Assert.True(e.IsPrivileged);
        Assert.Equal("HOST01.contoso.local", e.Hostname);
        Assert.Equal(100245, e.RecordId);
        Assert.Equal(new DateTimeOffset(2026, 6, 20, 13, 45, 12, 123, TimeSpan.Zero).AddTicks(4567),
            e.Timestamp);
    }

    [Fact]
    public void Failed4625_ExtractsFailureReasonFromSubStatus()
    {
        var e = _normalizer.Normalize(SampleEvents.Failed4625, Ctx);

        Assert.NotNull(e);
        Assert.Equal(4625, e!.EventId);
        Assert.True(e.IsFailure);
        Assert.False(e.IsSuccess);
        Assert.Equal("administrator", e.TargetUserName);
        Assert.Equal("NTLM", e.AuthenticationPackage);
        // SubStatus 0xC000006A => Bad password (preferred over Status).
        Assert.Equal("Bad password", e.FailureReason);
        // IPv4-mapped IPv6 prefix stripped.
        Assert.Equal("203.0.113.7", e.SourceIp);
    }

    [Fact]
    public void Explicit4648_UsesTargetUserAndServer()
    {
        var e = _normalizer.Normalize(SampleEvents.Explicit4648, Ctx);

        Assert.NotNull(e);
        Assert.Equal(4648, e!.EventId);
        Assert.Equal("Explicit credentials used", e.EventType);
        Assert.Equal("svc_admin", e.TargetUserName);
        Assert.Equal("DC01", e.TargetServer);
        Assert.False(e.IsSuccess);
        Assert.False(e.IsFailure);
    }

    [Fact]
    public void Privileged4672_IsFlaggedPrivileged()
    {
        var e = _normalizer.Normalize(SampleEvents.Privileged4672, Ctx);

        Assert.NotNull(e);
        Assert.Equal(4672, e!.EventId);
        Assert.True(e.IsPrivileged);
        Assert.True(e.IsSuccess);
        Assert.Equal("jdoe", e.TargetUserName);
        Assert.Equal(true, e.ElevatedToken);
    }

    [Fact]
    public void SparseEvent_DoesNotThrowAndKeepsKnownFields()
    {
        var e = _normalizer.Normalize(SampleEvents.SparseLogon, Ctx);

        Assert.NotNull(e);
        Assert.Equal("partial", e!.TargetUserName);
        Assert.Null(e.SourceIp);
        Assert.Null(e.LogonType);
        // Missing TimeCreated => MinValue, must not throw.
        Assert.Equal(DateTimeOffset.MinValue, e.Timestamp);
    }

    [Fact]
    public void MalformedXml_ReturnsNull()
    {
        var e = _normalizer.Normalize(SampleEvents.Malformed, Ctx);
        Assert.Null(e);
    }

    [Fact]
    public void UnsupportedEventId_ReturnsNull()
    {
        var e = _normalizer.Normalize(SampleEvents.UnsupportedEvent, Ctx);
        Assert.Null(e);
    }

    [Fact]
    public void MachineAccount_IsDetected()
    {
        var e = _normalizer.Normalize(
            SampleEvents.Logon4624.Replace("<Data Name='TargetUserName'>jdoe</Data>",
                                           "<Data Name='TargetUserName'>WKS9$</Data>"), Ctx);
        Assert.NotNull(e);
        Assert.True(e!.IsMachineAccount);
    }

    [Theory]
    [InlineData(2, "Interactive")]
    [InlineData(3, "Network")]
    [InlineData(10, "RemoteInteractive / RDP")]
    [InlineData(11, "CachedInteractive")]
    public void LogonTypeCatalog_Describes(int type, string expected) =>
        Assert.Equal(expected, LogonTypeCatalog.Describe(type));

    [Theory]
    [InlineData("0xC0000064", "User name does not exist")]
    [InlineData("0xC000006A", "Bad password")]
    [InlineData("0xC0000234", "Account locked out")]
    public void FailureReasonCatalog_DescribesSubStatus(string sub, string expected) =>
        Assert.Equal(expected, FailureReasonCatalog.Describe("0xC000006D", sub));

    [Fact]
    public void FailureReasonCatalog_IgnoresZeroSubStatus() =>
        Assert.Equal("Bad user name or password",
            FailureReasonCatalog.Describe("0xC000006D", "0x0"));
}
