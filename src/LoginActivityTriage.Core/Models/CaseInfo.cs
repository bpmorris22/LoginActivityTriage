namespace LoginActivityTriage.Core.Models;

/// <summary>Metadata for a triage case (one SQLite database).</summary>
public sealed class CaseInfo
{
    public long Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Analyst { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public string DatabasePath { get; set; } = string.Empty;
}
