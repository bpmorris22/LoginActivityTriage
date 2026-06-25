namespace LoginActivityTriage.Core.Models;

/// <summary>Outcome of importing one EVTX file.</summary>
public sealed class ImportedFileResult
{
    public required string FilePath { get; init; }
    public string? Hostname { get; set; }
    public string? LogSource { get; set; }
    public int RecordsRead { get; set; }
    public int EventsNormalised { get; set; }
    public int RecordsSkipped { get; set; }
    public bool Failed { get; set; }
    public string? Error { get; set; }
}

/// <summary>Aggregated result of an import run, surfaced to the import summary UI.</summary>
public sealed class ImportSummary
{
    public List<ImportedFileResult> Files { get; } = new();
    public List<string> Errors { get; } = new();

    public int FilesProcessed => Files.Count;
    public int FilesFailed => Files.Count(f => f.Failed);
    public int TotalRecordsRead => Files.Sum(f => f.RecordsRead);
    public int TotalEventsNormalised => Files.Sum(f => f.EventsNormalised);
    public int TotalSkipped => Files.Sum(f => f.RecordsSkipped);
}
