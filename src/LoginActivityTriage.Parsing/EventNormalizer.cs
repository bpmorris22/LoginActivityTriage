using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Facade that routes a parsed event to the first normaliser that owns it (by provider /
/// channel and event ID). New event families are enabled by registering more normalisers.
/// </summary>
public sealed class EventNormalizer
{
    private readonly IReadOnlyList<IEventNormalizer> _normalizers;

    public EventNormalizer(IEnumerable<IEventNormalizer>? normalizers = null)
    {
        _normalizers = normalizers?.ToList() ?? new List<IEventNormalizer>
        {
            new SecurityEventNormalizer(),
            new SystemEventNormalizer(),
            new TerminalServicesNormalizer(),
            new WinRmNormalizer(),
            new PowerShellNormalizer(),
            new SysmonNormalizer(),
        };
        CandidateEventIds = _normalizers.SelectMany(n => n.EventIds).ToHashSet();
    }

    /// <summary>
    /// Union of event IDs any normaliser may accept. Readers use it to skip rendering records
    /// (the expensive ToXml call) that cannot produce a row.
    /// </summary>
    public IReadOnlySet<int> CandidateEventIds { get; }

    /// <summary>Normalises an event XML string; returns null if unsupported, irrelevant or malformed.</summary>
    public NormalizedEvent? Normalize(string xml, NormalizationContext context)
    {
        var parsed = EventXmlData.TryParse(xml);
        if (parsed is null) return null;
        return Normalize(parsed, context);
    }

    public NormalizedEvent? Normalize(EventXmlData parsed, NormalizationContext context)
    {
        foreach (var n in _normalizers)
        {
            if (n.CanHandle(parsed))
                return n.Normalize(parsed, context);
        }
        return null;
    }
}
