using System.Globalization;
using System.Text;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Export;

/// <summary>
/// Writes normalised events to CSV using a small, dependency-free, RFC-4180
/// compliant writer (quotes fields containing comma, quote or newline).
/// </summary>
public static class CsvExporter
{
    private static readonly (string Header, Func<NormalizedEvent, string?> Value)[] Columns =
    {
        ("Timestamp",            e => e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
        ("Hostname",             e => e.Hostname),
        ("LogSource",            e => e.LogSource),
        ("EventId",              e => e.EventId.ToString(CultureInfo.InvariantCulture)),
        ("EventType",            e => e.EventType),
        ("User",                 e => e.TargetUserName),
        ("Domain",               e => e.TargetDomain),
        ("SourceIp",             e => e.SourceIp),
        ("SourcePort",           e => e.SourcePort),
        ("Workstation",          e => e.WorkstationName),
        ("LogonType",            e => e.LogonType?.ToString(CultureInfo.InvariantCulture)),
        ("LogonTypeDescription", e => e.LogonTypeDescription),
        ("AuthPackage",          e => e.AuthenticationPackage),
        ("ElevatedToken",        e => e.ElevatedToken is null ? null : (e.ElevatedToken.Value ? "Yes" : "No")),
        ("Process",              e => e.ProcessName),
        ("Status",               e => e.Status),
        ("FailureReason",        e => e.FailureReason),
    };

    public static void Export(IEnumerable<NormalizedEvent> events, string path)
    {
        using var writer = new StreamWriter(path, append: false, Encoding.UTF8);
        Write(events, writer);
    }

    public static string ToCsvString(IEnumerable<NormalizedEvent> events)
    {
        using var writer = new StringWriter();
        Write(events, writer);
        return writer.ToString();
    }

    private static void Write(IEnumerable<NormalizedEvent> events, TextWriter writer)
    {
        writer.WriteLine(string.Join(",", Columns.Select(c => Escape(c.Header))));
        foreach (var e in events)
            writer.WriteLine(string.Join(",", Columns.Select(c => Escape(c.Value(e)))));
    }

    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var needsQuote = value.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0;
        if (!needsQuote) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
