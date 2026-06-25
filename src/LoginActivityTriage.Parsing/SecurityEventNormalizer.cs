using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for Security-log authentication events. MVP scope covers the four
/// events that drive the logon timeline: 4624, 4625, 4648 and 4672. The shared
/// extraction below already reads the broader field set so additional Security
/// event IDs can be enabled by extending CanHandle.
/// </summary>
public sealed class SecurityEventNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = new() { 4624, 4625, 4648, 4672 };

    public bool CanHandle(int eventId) => Supported.Contains(eventId);

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev.EventId)) return null;

        var logonType = ev.GetInt("LogonType");

        var e = new NormalizedEvent
        {
            Timestamp = ev.TimeCreated ?? DateTimeOffset.MinValue,
            Hostname = ev.Computer ?? context.FallbackHostname,
            LogSource = context.LogSource ?? ev.Channel ?? "Security",
            EventId = ev.EventId,
            Provider = ev.Provider,
            RecordId = ev.RecordId,
            Channel = ev.Channel,
            EventType = WindowsEventCatalog.Describe(ev.EventId),
            TargetUserName = ev.GetAny("TargetUserName", "SubjectUserName"),
            TargetDomain = ev.GetAny("TargetDomainName", "SubjectDomainName"),
            Sid = ev.GetAny("TargetUserSid", "SubjectUserSid"),
            SourceIp = NormalizeIp(ev.GetAny("IpAddress", "SourceNetworkAddress")),
            SourcePort = ev.Get("IpPort"),
            WorkstationName = ev.GetAny("WorkstationName", "TargetServerName"),
            LogonType = logonType,
            LogonTypeDescription = logonType is null ? null : LogonTypeCatalog.Describe(logonType),
            AuthenticationPackage = ev.GetAny("AuthenticationPackageName", "LmPackageName"),
            LogonProcess = ev.Get("LogonProcessName"),
            ElevatedToken = ParseElevated(ev.Get("ElevatedToken")),
            ImpersonationLevel = ev.Get("ImpersonationLevel"),
            ProcessName = ev.Get("ProcessName"),
            ProcessId = ev.Get("ProcessId"),
            TargetServer = ev.GetAny("TargetServerName", "TargetInfo"),
            Status = ev.Get("Status"),
            SubStatus = ev.Get("SubStatus"),
            RawXml = ev.RawXml,
        };

        switch (ev.EventId)
        {
            case 4624:
                e.IsSuccess = true;
                break;
            case 4625:
                e.IsFailure = true;
                e.FailureReason = FailureReasonCatalog.Describe(e.Status, e.SubStatus);
                break;
            case 4648:
                e.TargetUserName = ev.GetAny("TargetUserName", "SubjectUserName");
                e.TargetServer = ev.Get("TargetServerName");
                break;
            case 4672:
                e.IsSuccess = true;
                e.ElevatedToken = true;
                break;
        }

        return e;
    }

    private static bool? ParseElevated(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return value.Trim() switch
        {
            "%%1842" => true,
            "%%1843" => false,
            _ => value.Contains("yes", StringComparison.OrdinalIgnoreCase) ? true
               : value.Contains("no", StringComparison.OrdinalIgnoreCase) ? false
               : (bool?)null,
        };
    }

    private static string? NormalizeIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        var trimmed = ip.Trim();
        if (trimmed == "-") return null;
        if (trimmed.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase))
            return trimmed[7..];
        return trimmed;
    }
}
