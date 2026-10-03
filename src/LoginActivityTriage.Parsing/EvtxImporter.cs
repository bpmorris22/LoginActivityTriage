using LoginActivityTriage.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace LoginActivityTriage.Parsing;

/// <summary>Progress notification raised while importing EVTX files.</summary>
public sealed class ImportProgress
{
    public required string CurrentFile { get; init; }
    public int FileIndex { get; init; }
    public int FileCount { get; init; }
    public int EventsNormalisedSoFar { get; init; }
}

/// <summary>Options controlling an import run.</summary>
public sealed class ImportOptions
{
    /// <summary>Drop records already seen in this run (and in <see cref="ExistingKeys"/>).</summary>
    public bool Deduplicate { get; init; } = true;

    /// <summary>Dedupe keys of events already in the case (re-import protection).</summary>
    public ISet<string>? ExistingKeys { get; init; }

    /// <summary>Optional UTC bounds; events outside are dropped.</summary>
    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }

    /// <summary>Optional predicate; events for which it returns false are dropped (e.g. noise accounts).</summary>
    public Func<NormalizedEvent, bool>? Keep { get; init; }
}

/// <summary>
/// Discovers EVTX files, reads and normalises authentication / remote-access events, and
/// streams the results to a sink. Designed to run on a background thread; it never throws
/// for a single bad file — failures are recorded in the returned <see cref="ImportSummary"/>.
/// </summary>
public sealed class EvtxImporter
{
    /// <summary>Live channels read in --live mode, in order.</summary>
    public static readonly IReadOnlyList<string> LiveChannels = new[]
    {
        "Security",
        "System",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-TerminalServices-RDPClient/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
    };

    private static readonly HashSet<string> GenericFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "logs", "evtx", "winevt", "system32", "windows", "eventlogs", "event logs", "c", "c%3a", "c$",
        "auto", "uploads", "ntfs", "file", "files", "collection", "output", "triage", "kape", "tout",
        "%5c%5c.%5cc%3a", "\\\\.\\c:", "vss", "results", "artifacts",
    };

    private static readonly System.Text.RegularExpressions.Regex VelociraptorCollection =
        new(@"^Collection-(?<h>.+?)-\d{4}-\d{2}-\d{2}T", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

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

    /// <summary>Recursively finds every *.evtx file under a folder, or returns the file itself.</summary>
    public static IReadOnlyList<string> DiscoverEvtxFiles(string path)
    {
        if (File.Exists(path))
            return path.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase) ? new[] { path } : Array.Empty<string>();
        if (!Directory.Exists(path)) return Array.Empty<string>();
        var opts = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            MatchCasing = MatchCasing.CaseInsensitive,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };
        return Directory.EnumerateFiles(path, "*.evtx", opts)
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Imports all EVTX files under a folder (or a single file).</summary>
    public ImportSummary Import(
        string path,
        Action<NormalizedEvent> onEvent,
        IProgress<ImportProgress>? progress = null,
        CancellationToken cancellation = default,
        ImportOptions? options = null)
    {
        var files = DiscoverEvtxFiles(path);
        var sources = files.Select(f => new Source(f, false)).ToList();
        return Run(sources, onEvent, progress, cancellation, options ?? new ImportOptions());
    }

    /// <summary>Imports the live event logs of this machine (requires administrator for Security).</summary>
    public ImportSummary ImportLive(
        Action<NormalizedEvent> onEvent,
        IProgress<ImportProgress>? progress = null,
        CancellationToken cancellation = default,
        ImportOptions? options = null)
    {
        var sources = LiveChannels.Select(c => new Source(c, true)).ToList();
        return Run(sources, onEvent, progress, cancellation, options ?? new ImportOptions());
    }

    private readonly record struct Source(string Name, bool IsChannel);

    private ImportSummary Run(
        IReadOnlyList<Source> sources,
        Action<NormalizedEvent> onEvent,
        IProgress<ImportProgress>? progress,
        CancellationToken cancellation,
        ImportOptions options)
    {
        var summary = new ImportSummary();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var normalisedTotal = 0;
        var wanted = _normalizer.CandidateEventIds;

        for (var i = 0; i < sources.Count; i++)
        {
            cancellation.ThrowIfCancellationRequested();
            var src = sources[i];
            var result = new ImportedFileResult { FilePath = src.Name };
            summary.Files.Add(result);

            result.Hostname = src.IsChannel ? Environment.MachineName : InferHostname(src.Name);
            result.LogSource = src.IsChannel ? FriendlyChannel(src.Name) : InferLogSource(src.Name);
            var context = new NormalizationContext
            {
                FallbackHostname = result.Hostname,
                LogSource = result.LogSource,
                SourceFile = src.Name,
            };

            progress?.Report(new ImportProgress
            {
                CurrentFile = src.Name,
                FileIndex = i,
                FileCount = sources.Count,
                EventsNormalisedSoFar = normalisedTotal,
            });

            if (src.IsChannel && !ChannelReadable(src.Name, result))
            {
                if (result.Failed) summary.Errors.Add($"{src.Name}: {result.Error}");
                continue;
            }

            try
            {
                void OnError(Exception ex)
                {
                    result.RecordsSkipped++;
                    _log.LogDebug(ex, "Skipped unreadable record in {File}", src.Name);
                }

                var records = src.IsChannel
                    ? _reader.ReadChannel(src.Name, OnError, wanted)
                    : _reader.Read(src.Name, OnError, wanted);

                foreach (var record in records)
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
                        _log.LogWarning(ex, "Normalisation failed for an event in {File}", src.Name);
                        continue;
                    }

                    if (normalised is null) continue;

                    if ((options.From is not null && normalised.Timestamp < options.From) ||
                        (options.To is not null && normalised.Timestamp > options.To) ||
                        (options.Keep is not null && !options.Keep(normalised)))
                    {
                        result.Filtered++;
                        continue;
                    }

                    if (options.Deduplicate)
                    {
                        var key = normalised.DedupeKey;
                        if (!seen.Add(key) || (options.ExistingKeys?.Contains(key) ?? false))
                        {
                            result.DuplicatesSkipped++;
                            continue;
                        }
                    }

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
                // A missing optional channel in live mode is routine, not an error worth alarming on.
                result.Failed = true;
                result.Error = ex.Message;
                summary.Errors.Add($"{(src.IsChannel ? src.Name : Path.GetFileName(src.Name))}: {ex.Message}");
                _log.LogError(ex, "Failed to import {File}", src.Name);
            }
        }

        progress?.Report(new ImportProgress
        {
            CurrentFile = string.Empty,
            FileIndex = sources.Count,
            FileCount = sources.Count,
            EventsNormalisedSoFar = normalisedTotal,
        });

        return summary;
    }

    /// <summary>
    /// Live channels: the reader tolerates query errors and silently returns nothing when access
    /// is denied, so probe the channel first and record why it cannot be read.
    /// </summary>
    private static bool ChannelReadable(string channel, ImportedFileResult result)
    {
        try
        {
            using var session = new System.Diagnostics.Eventing.Reader.EventLogSession();
            session.GetLogInformation(channel, System.Diagnostics.Eventing.Reader.PathType.LogName);
            return true;
        }
        catch (System.Diagnostics.Eventing.Reader.EventLogNotFoundException)
        {
            result.Error = "Channel not present on this machine";
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            result.Failed = true;
            result.Error = "Access denied - run elevated (administrator) to read this log";
            return false;
        }
        catch (Exception ex)
        {
            result.Failed = true;
            result.Error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// Best-effort hostname from the path. DFIR collections frequently name an ancestor folder
    /// after the host (…\HOST01\C\Windows\System32\winevt\Logs\Security.evtx); generic folder
    /// names are skipped while walking up.
    /// </summary>
    public static string? InferHostname(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        for (var depth = 0; depth < 12 && !string.IsNullOrEmpty(dir); depth++)
        {
            var name = new DirectoryInfo(dir).Name;
            if (string.IsNullOrEmpty(name) || name.EndsWith(':') || name.EndsWith(":\\")) return null;
            // Velociraptor offline collector: Collection-<host_with_underscores>-<yyyy-mm-ddThh_mm_ss...>
            var velo = VelociraptorCollection.Match(name);
            if (velo.Success) return velo.Groups["h"].Value.Replace('_', '.');
            if (!GenericFolders.Contains(name) && !name.StartsWith("HarddiskVolume", StringComparison.OrdinalIgnoreCase))
                return name;
            dir = Path.GetDirectoryName(dir);
        }
        return null;
    }

    /// <summary>Maps an EVTX file name to a friendly log-source label (decodes %4 as "/").</summary>
    public static string InferLogSource(string filePath)
    {
        // Velociraptor URL-encodes '%' as "%25", so "Foo%4Operational" arrives as "Foo%254Operational".
        var name = Path.GetFileNameWithoutExtension(filePath).Replace("%25", "%").Replace("%4", "/");
        return FriendlyChannel(name);
    }

    private static string FriendlyChannel(string name)
    {
        if (name.Equals("Security", StringComparison.OrdinalIgnoreCase) || name.StartsWith("Security", StringComparison.OrdinalIgnoreCase)) return "Security";
        if (name.Equals("System", StringComparison.OrdinalIgnoreCase) || name.StartsWith("System", StringComparison.OrdinalIgnoreCase)) return "System";
        if (name.Contains("RemoteConnectionManager", StringComparison.OrdinalIgnoreCase)) return "TerminalServices-RCM";
        if (name.Contains("LocalSessionManager", StringComparison.OrdinalIgnoreCase)) return "TerminalServices-LSM";
        if (name.Contains("RdpCoreTS", StringComparison.OrdinalIgnoreCase)) return "RdpCoreTS";
        if (name.Contains("RDPClient", StringComparison.OrdinalIgnoreCase)) return "RDPClient";
        if (name.Contains("WinRM", StringComparison.OrdinalIgnoreCase)) return "WinRM";
        if (name.Contains("Sysmon", StringComparison.OrdinalIgnoreCase)) return "Sysmon";
        if (name.Contains("PowerShell/Operational", StringComparison.OrdinalIgnoreCase)) return "PowerShell-Operational";
        if (name.Contains("PowerShell", StringComparison.OrdinalIgnoreCase)) return "Windows PowerShell";
        return name;
    }
}
