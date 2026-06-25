using System.Diagnostics.Eventing.Reader;

namespace LoginActivityTriage.Parsing;

/// <summary>One record streamed out of an EVTX file.</summary>
public readonly record struct EvtxRecord(int EventId, string Xml);

/// <summary>
/// Streams records out of an offline EVTX file using the Windows event log
/// reader. Individual record failures are isolated: a corrupt record is skipped
/// (reported via <paramref name="onRecordError"/>) rather than aborting the file.
/// </summary>
public sealed class EvtxFileReader
{
    /// <summary>
    /// Yields each event from the EVTX file as (EventId, Xml). Throws only on a
    /// failure to open the file at all; per-record errors are surfaced through
    /// the callback and skipped.
    /// </summary>
    public IEnumerable<EvtxRecord> Read(string evtxPath, Action<Exception>? onRecordError = null)
    {
        var query = new EventLogQuery(evtxPath, PathType.FilePath) { TolerateQueryErrors = true };
        using var reader = new EventLogReader(query);

        while (true)
        {
            EventRecord? record = null;
            string? xml = null;
            int eventId;

            try
            {
                record = reader.ReadEvent();
                if (record is null) yield break; // end of log
                eventId = record.Id;
                xml = record.ToXml();
            }
            catch (Exception ex)
            {
                onRecordError?.Invoke(ex);
                // Skip this record and keep going.
                record?.Dispose();
                continue;
            }
            finally
            {
                record?.Dispose();
            }

            if (xml is not null)
                yield return new EvtxRecord(eventId, xml);
        }
    }
}
