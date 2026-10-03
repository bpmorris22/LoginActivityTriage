namespace LoginActivityTriage.Core.Models;

public enum FindingSeverity { Info, Low, Medium, High, Critical }

/// <summary>A single result produced by the analytics rules.</summary>
public sealed class Finding
{
    public long Id { get; set; }
    public long CaseId { get; set; }
    public FindingSeverity Severity { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    /// <summary>UTC.</summary>
    public DateTimeOffset Timestamp { get; set; }
    public string? User { get; set; }
    public string? SourceIp { get; set; }
    public string? Host { get; set; }
    public string? RelatedEventIds { get; set; }
    public string? Reasoning { get; set; }
    /// <summary>MITRE ATT&amp;CK technique id(s), e.g. "T1021.002".</summary>
    public string? Mitre { get; set; }
    /// <summary>Number of underlying occurrences aggregated into this finding.</summary>
    public int Count { get; set; } = 1;
    /// <summary>Remote session id this finding was derived from, when applicable.</summary>
    public int? SessionRef { get; set; }
}
