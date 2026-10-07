namespace LoginActivityTriage.Core.Models;

/// <summary>Outcome of importing one EVTX file (or live channel).</summary>
public sealed class ImportedFileResult
{
    public required string FilePath { get; init; }
    public string? Hostname { get; set; }
    public string? LogSource { get; set; }
    public int RecordsRead { get; set; }
    public int EventsNormalised { get; set; }
    public int RecordsSkipped { get; set; }
    public int DuplicatesSkipped { get; set; }
    public int Filtered { get; set; }
    public bool Failed { get; set; }
    public string? Error { get; set; }
    /// <summary>SHA-256 (lower-case hex) of the source file as it was read; null for live channels or when hashing was skipped.</summary>
    public string? Sha256 { get; set; }
    /// <summary>Size of the source file in bytes; null for live channels.</summary>
    public long? SizeBytes { get; set; }
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
    public int TotalDuplicates => Files.Sum(f => f.DuplicatesSkipped);
    public int TotalFiltered => Files.Sum(f => f.Filtered);
}
