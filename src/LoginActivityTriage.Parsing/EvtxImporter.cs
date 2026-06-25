using LoginActivityTriage.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LoginActivityTriage.Parsing;

/// <summary>Progress notification raised while importing a folder of EVTX files.</summary>
public sealed class ImportProgress
{
    public required string CurrentFile { get; init; }
    public int FileIndex { get; init; }
    public int FileCount { get; init; }
    public int EventsNormalisedSoFar { get; init; }
}

/// <summary>
/// Discovers EVTX files under a folder, reads and normalises authentication
/// events, and streams the results to a sink. Designed to run on a background
/// thread; it never throws for a single bad file - failures are recorded in the
/// returned <see cref="ImportSummary"/>.
/// </summary>
public sealed class EvtxImporter
{
    private readonly EventNormalizer _normalizer;
    private readonly EvtxFileReader _reader;
    private readonly ILogger _log;

    public EvtxImporter(
        EventNormalizer? normalizer = null,
        EvtxFileReader? reader = null,
        ILogger<EvtxImporter>? logger = null)
    {
        _normalizer = normalizer ?? new EventNormalizer();
        _reader = reader ?? new EvtxFileReader();
        _log = logger ?? NullLogger<EvtxImporter>.Instance;
    }

    /// <summary>Recursively finds every *.evtx file under <paramref name="folder"/>.</summary>
    public static IReadOnlyList<string> DiscoverEvtxFiles(string folder) =>
        Directory.Exists(folder)
            ? Directory.EnumerateFiles(folder, "*.evtx", SearchOption.AllDirectories)
                .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList()
            : Array.Empty<string>();

    /// <summary>
    /// Imports all EVTX files under a folder. Each normalised event is passed to
    /// <paramref name="onEvent"/> (e.g. to batch-insert into SQLite). Returns a
    /// summary including per-file counts and any errors.
    /// </summary>
    public ImportSummary Import(
        string folder,
        Action<NormalizedEvent> onEvent,
        IProgress<ImportProgress>? progress = null,
        CancellationToken cancellation = default)
    {
        var summary = new ImportSummary();
        var files = DiscoverEvtxFiles(folder);
        var normalisedTotal = 0;

        for (var i = 0; i < files.Count; i++)
        {
            cancellation.ThrowIfCancellationRequested();
            var file = files[i];
            var result = new ImportedFileResult { FilePath = file };
            summary.Files.Add(result);

            result.Hostname = InferHostname(file);
            result.LogSource = InferLogSource(file);
            var context = new NormalizationContext
            {
                FallbackHostname = result.Hostname,
                LogSource = result.LogSource,
            };

            progress?.Report(new ImportProgress
            {
                CurrentFile = file,
                FileIndex = i,
                FileCount = files.Count,
                EventsNormalisedSoFar = normalisedTotal,
            });

            try
            {
                foreach (var record in _reader.Read(file, ex =>
                         {
                             result.RecordsSkipped++;
                             _log.LogDebug(ex, "Skipped malformed record in {File}", file);
                         }))
                {
                    cancellation.ThrowIfCancellationRequested();
                    result.RecordsRead++;

                    NormalizedEvent? normalised;
                    try
                    {
                        normalised = _normalizer.Normalize(record.Xml, context);
                    }
                    catch (Exception ex)
                    {
                        result.RecordsSkipped++;
                        _log.LogWarning(ex, "Normalisation failed for an event in {File}", file);
                        continue;
                    }

                    if (normalised is null) continue;

                    onEvent(normalised);
                    result.EventsNormalised++;
                    normalisedTotal++;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                result.Failed = true;
                result.Error = ex.Message;
                summary.Errors.Add($"{Path.GetFileName(file)}: {ex.Message}");
                _log.LogError(ex, "Failed to import {File}", file);
            }
        }

        progress?.Report(new ImportProgress
        {
            CurrentFile = string.Empty,
            FileIndex = files.Count,
            FileCount = files.Count,
            EventsNormalisedSoFar = normalisedTotal,
        });

        return summary;
    }

    /// <summary>
    /// Best-effort hostname from the path. DFIR collections frequently name the
    /// parent folder after the host (e.g. ...\COLLECT\HOST01\Security.evtx).
    /// </summary>
    public static string? InferHostname(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (string.IsNullOrEmpty(dir)) return null;
        var name = new DirectoryInfo(dir).Name;
        // Skip generic container folder names.
        if (name.Equals("logs", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("evtx", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("winevt", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("Logs", StringComparison.OrdinalIgnoreCase))
            return null;
        return name;
    }

    /// <summary>Maps a file name to a friendly log-source label.</summary>
    public static string InferLogSource(string filePath)
    {
        var name = Path.GetFileNameWithoutExtension(filePath);
        if (name.StartsWith("Security", StringComparison.OrdinalIgnoreCase)) return "Security";
        if (name.StartsWith("System", StringComparison.OrdinalIgnoreCase)) return "System";
        if (name.Contains("RemoteConnectionManager", StringComparison.OrdinalIgnoreCase)) return "TerminalServices-RCM";
        if (name.Contains("LocalSessionManager", StringComparison.OrdinalIgnoreCase)) return "TerminalServices-LSM";
        if (name.Contains("PowerShell", StringComparison.OrdinalIgnoreCase)) return "PowerShell";
        return name;
    }
}
