using System.Diagnostics.Eventing.Reader;

namespace LoginActivityTriage.Parsing;

/// <summary>One record streamed out of an EVTX file or live channel.</summary>
public readonly record struct EvtxRecord(int EventId, string Xml);

/// <summary>
/// Streams records out of an offline EVTX file (or a live channel) using the Windows event log
/// reader. Individual record failures are isolated: a corrupt record is skipped (reported via
/// the error callback) rather than aborting the file. A run of consecutive failures aborts the
/// file so a reader that cannot advance never loops forever.
/// </summary>
public sealed class EvtxFileReader
{
    /// <summary>Consecutive per-record failures tolerated before the file is abandoned.</summary>
    public int MaxConsecutiveErrors { get; init; } = 200;

    /// <summary>Yields each event from an EVTX file.</summary>
    public IEnumerable<EvtxRecord> Read(string evtxPath, Action<Exception>? onRecordError = null,
        IReadOnlySet<int>? wantedEventIds = null) =>
        ReadQuery(new EventLogQuery(ApiPath(evtxPath), PathType.FilePath) { TolerateQueryErrors = true },
            onRecordError, wantedEventIds);

    /// <summary>
    /// The path to hand the Windows event log API. It is not long-path aware: a file path of
    /// MAX_PATH (260) characters or more fails with status 3 ("cannot find the path") even with
    /// LongPathsEnabled, and Velociraptor / KAPE collection trees routinely go past that. The
    /// \\?\ extended-length form of the same path opens normally. Shorter paths are unchanged.
    /// </summary>
    public static string ApiPath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.StartsWith(@"\\?\", StringComparison.Ordinal)
            || path.StartsWith(@"\\.\", StringComparison.Ordinal))
            return path;
        var full = Path.GetFullPath(path);
        if (full.Length < 260) return path;
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full[2..] : @"\\?\" + full;
    }

    /// <summary>Yields each event from a live channel, e.g. "Security" (needs admin rights).</summary>
    public IEnumerable<EvtxRecord> ReadChannel(string channel, Action<Exception>? onRecordError = null,
        IReadOnlySet<int>? wantedEventIds = null) =>
        ReadQuery(new EventLogQuery(channel, PathType.LogName) { TolerateQueryErrors = true },
            onRecordError, wantedEventIds);

    private IEnumerable<EvtxRecord> ReadQuery(EventLogQuery query, Action<Exception>? onRecordError,
        IReadOnlySet<int>? wanted)
    {
        using var reader = new EventLogReader(query);
        var consecutiveErrors = 0;
        var statusChecked = false;
        string? queryFailure = null;

        while (true)
        {
            EventRecord? record = null;
            string? xml = null;
            int eventId;

            try
            {
                record = reader.ReadEvent();
                // TolerateQueryErrors keeps per-record recovery, but it also turns "this is not an
                // event log" into an empty result: the per-log status is the only signal left.
                if (!statusChecked)
                {
                    statusChecked = true;
                    queryFailure = QueryFailure(reader);
                }
                if (record is null && queryFailure is null) yield break; // end of log
                eventId = record?.Id ?? 0;
                // Rendering XML is the expensive step; skip records no normaliser can use.
                if (record is not null && queryFailure is null && (wanted is null || wanted.Contains(eventId)))
                    xml = record.ToXml();
                consecutiveErrors = 0;
            }
            catch (Exception ex)
            {
                onRecordError?.Invoke(ex);
                if (++consecutiveErrors >= MaxConsecutiveErrors)
                    throw new InvalidDataException(
                        $"Abandoned after {consecutiveErrors} consecutive unreadable records (file may be corrupt).", ex);
                continue;
            }
            finally
            {
                record?.Dispose();
            }

            if (queryFailure is not null) throw new InvalidDataException(queryFailure);
            if (xml is not null)
                yield return new EvtxRecord(eventId, xml);
        }
    }

    /// <summary>Describes a non-zero per-log query status (e.g. 1287 for a file that is not an EVTX), or null.</summary>
    private static string? QueryFailure(EventLogReader reader)
    {
        try
        {
            foreach (var s in reader.LogStatus)
                if (s.StatusCode != 0)
                    return $"Not a readable event log (status {s.StatusCode}: {new System.ComponentModel.Win32Exception(s.StatusCode).Message})";
        }
        catch (Exception)
        {
            // LogStatus is informational; a reader that cannot report it keeps its records.
        }
        return null;
    }
}
