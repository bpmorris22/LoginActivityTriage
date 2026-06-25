using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Facade that routes a parsed event to the first normaliser that can handle it.
/// New event families are enabled by registering additional normalisers.
/// </summary>
public sealed class EventNormalizer
{
    private readonly IReadOnlyList<IEventNormalizer> _normalizers;

    public EventNormalizer(IEnumerable<IEventNormalizer>? normalizers = null)
    {
        _normalizers = normalizers?.ToList() ?? new List<IEventNormalizer>
        {
            new SecurityEventNormalizer(),
            new TerminalServicesNormalizer(),
        };
    }

    /// <summary>Normalises an event XML string; returns null if unsupported or malformed.</summary>
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
            if (n.CanHandle(parsed.EventId))
                return n.Normalize(parsed, context);
        }
        return null;
    }
}
