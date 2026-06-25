using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>Context the normaliser uses when event fields are absent.</summary>
public sealed class NormalizationContext
{
    /// <summary>Hostname inferred from the file path, used when the event omits Computer.</summary>
    public string? FallbackHostname { get; init; }

    /// <summary>Friendly log source label, e.g. "Security".</summary>
    public string? LogSource { get; init; }
}

/// <summary>Turns a parsed event into a normalised row, or null if unsupported.</summary>
public interface IEventNormalizer
{
    bool CanHandle(int eventId);
    NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context);
}
