using System.Globalization;
using System.Text;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Export;

/// <summary>A CSV column: header plus value selector.</summary>
public sealed record CsvColumn<T>(string Header, Func<T, string?> Value);

/// <summary>
/// Dependency-free RFC-4180 CSV writer (UTF-8 with BOM so Excel / Timeline Explorer detect it).
/// Values that a spreadsheet would execute as a formula (= + - @ tab CR at the start) are
/// prefixed with an apostrophe: event fields such as failed-logon user names are attacker
/// controlled. Timestamps are ISO-8601 UTC with a "Z" suffix.
/// </summary>
public static class CsvExporter
{
    public const string TimestampFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'";

    public static string Ts(DateTimeOffset t) =>
        t == DateTimeOffset.MinValue ? string.Empty : t.UtcDateTime.ToString(TimestampFormat, CultureInfo.InvariantCulture);

    private static string? Bool(bool? b) => b is null ? null : (b.Value ? "Yes" : "No");
    private static string? Int(int? i) => i?.ToString(CultureInfo.InvariantCulture);
    private static string? Long(long? i) => i?.ToString(CultureInfo.InvariantCulture);

    /// <summary>Full event column set (the HTA viewer keys on these header names).</summary>
    public static readonly IReadOnlyList<CsvColumn<NormalizedEvent>> EventColumns = new CsvColumn<NormalizedEvent>[]
    {
        new("Timestamp", e => Ts(e.Timestamp)),
        new("Hostname", e => e.Hostname),
        new("LogSource", e => e.LogSource),
        new("Channel", e => e.Channel),
        new("Provider", e => e.Provider),
        new("EventId", e => Int(e.EventId)),
        new("RecordId", e => Long(e.RecordId)),
        new("EventType", e => e.EventType),
        new("Activity", e => e.Activity),
        new("Technique", e => e.Technique),
        new("TechniqueDetail", e => e.TechniqueDetail),
        new("Direction", e => e.Technique is null ? null : (e.IsOutbound ? "Outbound" : "Inbound")),
        new("SessionRef", e => Int(e.RemoteSessionRef)),
        new("Result", e => e.IsSuccess ? "Success" : e.IsFailure ? "Failure" : null),
        // Events that carry only a well-known SID (7045 installs by SYSTEM...) show its account name.
        new("User", e => e.TargetUserName ?? AccountClassifier.WellKnownSidName(e.Sid)),
        new("Domain", e => e.TargetDomain ?? (e.TargetUserName is null && AccountClassifier.WellKnownSidName(e.Sid) is not null ? "NT AUTHORITY" : null)),
        new("Sid", e => e.Sid),
        new("SubjectUser", e => e.SubjectUserName),
        new("SubjectDomain", e => e.SubjectDomain),
        new("LogonId", e => e.LogonId),
        new("SubjectLogonId", e => e.SubjectLogonId),
        new("LinkedLogonId", e => e.LinkedLogonId),
        new("SessionId", e => e.SessionId),
        new("SourceIp", e => e.SourceIp),
        new("SourcePort", e => e.SourcePort),
        new("Workstation", e => e.WorkstationName),
        new("LogonType", e => Int(e.LogonType)),
        new("LogonTypeDescription", e => e.LogonTypeDescription),
        new("AuthPackage", e => e.AuthenticationPackage),
        new("LogonProcess", e => e.LogonProcess),
        new("ElevatedToken", e => Bool(e.ElevatedToken)),
        new("Privileged", e => e.IsPrivileged ? "Yes" : null),
        new("ImpersonationLevel", e => e.ImpersonationLevel),
        new("TargetServer", e => e.TargetServer),
        new("Process", e => e.ProcessName),
        new("ProcessId", e => e.ProcessId),
        new("ParentProcess", e => e.ParentProcessName),
        new("CommandLine", e => e.CommandLine),
        new("ServiceName", e => e.ServiceName),
        new("ServiceFile", e => e.ServiceFileName),
        new("ServiceAccount", e => e.ServiceAccount),
        new("TaskName", e => e.TaskName),
        new("ShareName", e => e.ShareName),
        new("ShareTarget", e => e.RelativeTargetName),
        new("GroupName", e => e.GroupName),
        new("TicketEncryption", e => e.TicketEncryptionType),
        new("Status", e => e.Status),
        new("SubStatus", e => e.SubStatus),
        new("FailureReason", e => e.FailureReason),
        new("PrivilegeList", e => e.PrivilegeList),
        new("Details", e => e.Details),
        new("SourceFile", e => e.SourceFile),
    };

    public static readonly IReadOnlyList<CsvColumn<RemoteSession>> SessionColumns = new CsvColumn<RemoteSession>[]
    {
        new("SessionRef", s => Int(s.Id)),
        new("Start", s => Ts(s.Start)),
        new("End", s => Ts(s.End)),
        new("DurationMinutes", s => Math.Round(s.Duration.TotalMinutes, 1).ToString(CultureInfo.InvariantCulture)),
        new("Technique", s => s.Technique),
        new("Variant", s => s.Variant),
        new("Direction", s => s.Direction),
        new("Host", s => s.Host),
        new("TargetHost", s => s.TargetHost),
        new("TargetHostName", s => s.TargetHostName),
        new("CredentialsUsed", s => s.CredentialsUsed),
        new("User", s => s.User),
        new("Domain", s => s.Domain),
        new("InferredUser", s => s.InferredUser),
        new("SourceIp", s => s.SourceIp),
        new("SourceHost", s => s.SourceHost),
        new("LogonId", s => s.LogonId),
        new("LogonType", s => Int(s.LogonType)),
        new("AuthPackage", s => s.AuthPackage),
        new("Confidence", s => s.Confidence),
        new("Detail", s => s.Detail),
        new("Commands", s => s.Commands),
        new("EventCount", s => Int(s.EventCount)),
        new("EventIds", s => s.EventIds),
        new("Evidence", s => s.Evidence),
    };

    public static readonly IReadOnlyList<CsvColumn<Finding>> FindingColumns = new CsvColumn<Finding>[]
    {
        new("Severity", f => f.Severity.ToString()),
        new("Rule", f => f.RuleName),
        new("Timestamp", f => Ts(f.Timestamp)),
        new("Host", f => f.Host),
        new("User", f => f.User),
        new("SourceIp", f => f.SourceIp),
        new("Count", f => Int(f.Count)),
        new("Mitre", f => f.Mitre),
        new("SessionRef", f => Int(f.SessionRef)),
        new("Description", f => f.Description),
        new("RelatedEventIds", f => f.RelatedEventIds),
        new("Reasoning", f => f.Reasoning),
    };

    public static readonly IReadOnlyList<CsvColumn<UserPivot>> UserPivotColumns = new CsvColumn<UserPivot>[]
    {
        new("User", p => p.User), new("Sid", p => p.Sid), new("SystemAccount", p => p.IsSystemAccount ? "Yes" : null),
        new("FirstSeen", p => Ts(p.FirstSeen)), new("LastSeen", p => Ts(p.LastSeen)),
        new("HostCount", p => Int(p.HostCount)), new("SourceIpCount", p => Int(p.SourceIpCount)),
        new("Successful", p => Int(p.Successful)), new("Failed", p => Int(p.Failed)), new("RdpInbound", p => Int(p.Rdp)),
        new("RemoteExec", p => Int(p.RemoteExec)), new("RemoteAccessTool", p => Int(p.RemoteAccessTool)),
        new("UsedOthersCreds", p => Int(p.UsedOthersCreds)), new("CredsUsedByOthers", p => Int(p.CredsUsedByOthers)),
        new("Privileged", p => Int(p.Privileged)), new("GroupChanges", p => Int(p.GroupChanges)),
        new("SuspicionScore", p => Int(p.SuspicionScore)), new("Hosts", p => p.Hosts), new("SourceIps", p => p.SourceIps),
    };

    public static readonly IReadOnlyList<CsvColumn<SourceIpPivot>> SourceIpPivotColumns = new CsvColumn<SourceIpPivot>[]
    {
        new("SourceIp", p => p.SourceIp), new("FirstSeen", p => Ts(p.FirstSeen)), new("LastSeen", p => Ts(p.LastSeen)),
        new("PrivateAddress", p => p.IsPrivateAddress ? "Yes" : "No"),
        new("UniqueUsers", p => Int(p.UniqueUsers)), new("UniqueHosts", p => Int(p.UniqueHosts)),
        new("Successful", p => Int(p.Successful)), new("Failed", p => Int(p.Failed)), new("RdpInbound", p => Int(p.Rdp)),
        new("RemoteExec", p => Int(p.RemoteExec)), new("Explicit", p => Int(p.Explicit)),
        new("Privileged", p => Int(p.Privileged)), new("SuspicionScore", p => Int(p.SuspicionScore)),
        new("Users", p => p.Users), new("Hosts", p => p.Hosts),
    };

    public static readonly IReadOnlyList<CsvColumn<HostPivot>> HostPivotColumns = new CsvColumn<HostPivot>[]
    {
        new("Host", p => p.Host), new("FirstSeen", p => Ts(p.FirstSeen)), new("LastSeen", p => Ts(p.LastSeen)),
        new("Users", p => Int(p.Users)), new("SourceIps", p => Int(p.SourceIps)),
        new("Successful", p => Int(p.Successful)), new("Failed", p => Int(p.Failed)),
        new("RdpInbound", p => Int(p.Rdp)), new("RdpOutbound", p => Int(p.RdpOutbound)),
        new("RemoteExec", p => Int(p.RemoteExec)), new("RemoteAccessTool", p => Int(p.RemoteAccessTool)),
        new("ServiceInstalls", p => Int(p.ServiceInstalls)),
        new("Privileged", p => Int(p.Privileged)), new("LogClears", p => Int(p.LogClears)),
        new("TimeZone", p => p.TimeZone),
    };

    public static readonly IReadOnlyList<CsvColumn<RemoteHostPivot>> RemoteHostPivotColumns = new CsvColumn<RemoteHostPivot>[]
    {
        new("RemoteHost", p => p.RemoteHost), new("Name", p => p.Name), new("Collected", p => p.IsCollected ? "Yes" : null),
        new("FirstSeen", p => Ts(p.FirstSeen)), new("LastSeen", p => Ts(p.LastSeen)),
        new("Connections", p => Int(p.Connections)), new("Rdp", p => Int(p.Rdp)), new("RemoteExec", p => Int(p.RemoteExec)),
        new("ExplicitCreds", p => Int(p.ExplicitCreds)), new("Techniques", p => p.Techniques),
        new("FromHosts", p => p.FromHosts), new("Users", p => p.Users), new("InferredUsers", p => p.InferredUsers),
        new("CredentialsUsed", p => p.CredentialsUsed),
    };

    public static readonly IReadOnlyList<CsvColumn<ImportedFileResult>> FileColumns = new CsvColumn<ImportedFileResult>[]
    {
        new("File", f => f.FilePath), new("Hostname", f => f.Hostname), new("LogSource", f => f.LogSource),
        new("SizeBytes", f => Long(f.SizeBytes)), new("Sha256", f => f.Sha256),
        new("RecordsRead", f => Int(f.RecordsRead)), new("EventsKept", f => Int(f.EventsNormalised)),
        new("Skipped", f => Int(f.RecordsSkipped)), new("Duplicates", f => Int(f.DuplicatesSkipped)),
        new("Filtered", f => Int(f.Filtered)), new("Failed", f => f.Failed ? "Yes" : "No"), new("Error", f => f.Error),
    };

    // ---- writers ----

    /// <summary>Exports events with the full column set.</summary>
    public static void Export(IEnumerable<NormalizedEvent> events, string path) => Write(path, events, EventColumns);

    public static string ToCsvString(IEnumerable<NormalizedEvent> events)
    {
        using var writer = new StringWriter();
        Write(writer, events, EventColumns);
        return writer.ToString();
    }

    public static void Write<T>(string path, IEnumerable<T> rows, IReadOnlyList<CsvColumn<T>> columns)
    {
        using var writer = new StreamWriter(path, append: false, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        Write(writer, rows, columns);
    }

    public static void Write<T>(TextWriter writer, IEnumerable<T> rows, IReadOnlyList<CsvColumn<T>> columns)
    {
        writer.Write(string.Join(",", columns.Select(c => Escape(c.Header))));
        writer.Write("\r\n");
        foreach (var row in rows)
        {
            for (var i = 0; i < columns.Count; i++)
            {
                if (i > 0) writer.Write(',');
                writer.Write(Escape(columns[i].Value(row)));
            }
            writer.Write("\r\n");
        }
    }

    private static readonly char[] QuoteTriggers = { ',', '"', '\n', '\r' };

    /// <summary>RFC-4180 escape with spreadsheet formula-injection neutralisation.</summary>
    public static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
            value = "'" + value;
        var needsQuote = value.IndexOfAny(QuoteTriggers) >= 0;
        if (!needsQuote) return value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }
}
