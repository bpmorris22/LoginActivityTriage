using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>Context the normaliser uses when event fields are absent.</summary>
public sealed class NormalizationContext
{
    /// <summary>Hostname inferred from the file path, used when the event omits Computer.</summary>
    public string? FallbackHostname { get; init; }

    /// <summary>Friendly log source label, e.g. "Security".</summary>
    public string? LogSource { get; init; }

    /// <summary>EVTX path or live channel the record came from.</summary>
    public string? SourceFile { get; init; }
}

/// <summary>
/// Turns a parsed event into a normalised row, or null if the record is not relevant.
/// Routing is by provider / channel AND event ID: event IDs collide across providers
/// (e.g. Kernel-Boot 25 in System vs TerminalServices-LSM 25).
/// </summary>
public interface IEventNormalizer
{
    /// <summary>Event IDs this normaliser may handle (used to skip rendering of irrelevant records).</summary>
    IReadOnlyCollection<int> EventIds { get; }

    /// <summary>True when this normaliser owns the event (provider/channel and ID match).</summary>
    bool CanHandle(EventXmlData ev);

    NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context);
}

/// <summary>Shared construction helpers for normalisers.</summary>
internal static class NormalizerBase
{
    /// <summary>Builds the common envelope (time, host, provider, record id, raw XML).</summary>
    public static NormalizedEvent Envelope(EventXmlData ev, NormalizationContext ctx, string eventType, string defaultSource) =>
        new()
        {
            Timestamp = ev.TimeCreated ?? DateTimeOffset.MinValue,
            Hostname = ev.Computer ?? ctx.FallbackHostname,
            // The record's own channel beats the file name (exports are often renamed).
            LogSource = FriendlyChannel(ev.Channel) ?? ctx.LogSource ?? defaultSource,
            SourceFile = ctx.SourceFile,
            EventId = ev.EventId,
            Provider = ev.Provider,
            RecordId = ev.RecordId,
            Channel = ev.Channel,
            EventType = eventType,
            RawXml = ev.RawXml,
        };

    /// <summary>Applies a remote-exec classification to an event.</summary>
    public static void Apply(NormalizedEvent e, RemoteExecMatch? m)
    {
        if (m is null) return;
        e.Technique = m.Value.Technique;
        e.TechniqueDetail = m.Value.Variant;
        e.IsOutbound = m.Value.Outbound;
    }

    /// <summary>Sets TargetUserName / TargetDomain from a "DOMAIN\user" or "user@realm" value.</summary>
    public static void SetUser(NormalizedEvent e, string? user, string? domain = null)
    {
        var (u, d) = UserKey.Split(user);
        e.TargetUserName = u;
        e.TargetDomain = domain ?? d;
    }

    /// <summary>Joins non-empty parts with " | ", truncating very long values.</summary>
    public static string? Join(params string?[] parts)
    {
        var list = parts.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => Truncate(p!.Trim(), 400)).ToList();
        return list.Count == 0 ? null : string.Join(" | ", list);
    }

    public static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    private static string? FriendlyChannel(string? channel) => channel switch
    {
        null => null,
        _ when channel.Contains("LocalSessionManager", StringComparison.OrdinalIgnoreCase) => "TerminalServices-LSM",
        _ when channel.Contains("RemoteConnectionManager", StringComparison.OrdinalIgnoreCase) => "TerminalServices-RCM",
        _ when channel.Contains("RdpCoreTS", StringComparison.OrdinalIgnoreCase) => "RdpCoreTS",
        _ when channel.Contains("RDPClient", StringComparison.OrdinalIgnoreCase) => "RDPClient",
        _ when channel.Contains("WinRM", StringComparison.OrdinalIgnoreCase) => "WinRM",
        _ when channel.Contains("PowerShell/Operational", StringComparison.OrdinalIgnoreCase) => "PowerShell-Operational",
        _ when channel.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) => "Sysmon",
        _ => channel,
    };
}
