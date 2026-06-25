namespace LoginActivityTriage.Core.Models;

public enum FindingSeverity { Info, Low, Medium, High, Critical }

/// <summary>A single result produced by the suspicious-sequence analytics rules.</summary>
public sealed class Finding
{
    public long Id { get; set; }
    public long CaseId { get; set; }
    public FindingSeverity Severity { get; set; }
    public string RuleName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; }
    public string? User { get; set; }
    public string? SourceIp { get; set; }
    public string? Host { get; set; }
    public string? RelatedEventIds { get; set; }
    public string? Reasoning { get; set; }
}
