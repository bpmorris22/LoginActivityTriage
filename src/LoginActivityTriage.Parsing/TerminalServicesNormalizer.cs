using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for Terminal-Services RDP events (1149 and LSM session events
/// 21/22/24/25/39/40). Included beyond the MVP four so the RDP Activity view has
/// data to correlate; field names differ from the Security schema.
/// </summary>
public sealed class TerminalServicesNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = new() { 1149, 21, 22, 24, 25, 39, 40 };

    public bool CanHandle(int eventId) => Supported.Contains(eventId);

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev.EventId)) return null;

        var e = new NormalizedEvent
        {
            Timestamp = ev.TimeCreated ?? DateTimeOffset.MinValue,
            Hostname = ev.Computer ?? context.FallbackHostname,
            LogSource = context.LogSource ?? ev.Channel ?? "TerminalServices",
            EventId = ev.EventId,
            Provider = ev.Provider,
            RecordId = ev.RecordId,
            Channel = ev.Channel,
            EventType = WindowsEventCatalog.Describe(ev.EventId),
            TargetUserName = ev.GetAny("User", "Param1", "TargetUserName"),
            TargetDomain = ev.Get("Domain"),
            SourceIp = ev.GetAny("Address", "Param3", "SourceNetworkAddress", "ClientName"),
            LogonType = ev.EventId == 1149 ? 10 : null,
            LogonTypeDescription = ev.EventId == 1149 ? LogonTypeCatalog.Describe(10) : null,
            RawXml = ev.RawXml,
        };

        if (ev.EventId == 1149)
            e.IsSuccess = true;

        return e;
    }
}
