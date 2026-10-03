using System.Globalization;
using System.Net;
using System.Text;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Export;

/// <summary>
/// Produces simple, self-contained HTML reports suitable for attaching to an
/// investigation note. No external CSS/JS; everything is inlined. All times UTC.
/// </summary>
public static class HtmlExporter
{
    private static string Ts(DateTimeOffset t) => CsvExporter.Ts(t);

    private static readonly (string Header, Func<NormalizedEvent, string?> Value)[] Columns =
    {
        ("Timestamp (UTC)", e => Ts(e.Timestamp)),
        ("Host",        e => e.Hostname),
        ("Event",       e => $"{e.EventId} {e.EventType}"),
        ("Technique",   e => e.Technique is null ? null : $"{e.Technique}{(e.IsOutbound ? " (outbound)" : "")}"),
        ("User",        e => e.TargetUserName ?? Core.Mapping.AccountClassifier.WellKnownSidName(e.Sid)),
        ("Source IP",   e => e.SourceIp),
        ("Logon Type",  e => e.LogonType is null ? null : $"{e.LogonType} {e.LogonTypeDescription}"),
        ("Auth",        e => e.AuthenticationPackage),
        ("Logon ID",    e => e.LogonId),
        ("Details",     e => e.Details),
        ("Failure",     e => e.FailureReason),
    };

    public static void ExportEvents(IEnumerable<NormalizedEvent> events, string path, string title)
    {
        var sb = new StringBuilder();
        Header(sb, title);
        sb.Append("<table><thead><tr>");
        foreach (var c in Columns) sb.Append("<th>").Append(Enc(c.Header)).Append("</th>");
        sb.Append("</tr></thead><tbody>");
        foreach (var e in events)
        {
            var cls = e.IsFailure ? " class=\"fail\"" : e.Technique is not null && e.Technique != "RDP" ? " class=\"rex\""
                : e.IsPrivileged ? " class=\"priv\"" : "";
            sb.Append("<tr").Append(cls).Append('>');
            foreach (var c in Columns)
                sb.Append("<td>").Append(Enc(c.Value(e))).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");
        Footer(sb);
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    public static void ExportSessions(IEnumerable<RemoteSession> sessions, string path, string title)
    {
        var sb = new StringBuilder();
        Header(sb, title);
        sb.Append("<table><thead><tr><th>#</th><th>Start (UTC)</th><th>End (UTC)</th><th>Technique</th><th>Direction</th>")
          .Append("<th>Host</th><th>User</th><th>Source</th><th>Detail</th><th>Commands</th><th>Confidence</th></tr></thead><tbody>");
        foreach (var s in sessions)
        {
            sb.Append(s.Technique == "RDP" ? "<tr>" : "<tr class=\"rex\">")
              .Append("<td>").Append(s.Id).Append("</td>")
              .Append("<td>").Append(Enc(Ts(s.Start))).Append("</td>")
              .Append("<td>").Append(Enc(Ts(s.End))).Append("</td>")
              .Append("<td>").Append(Enc(s.Technique + (s.Variant is null ? "" : $" ({s.Variant})"))).Append("</td>")
              .Append("<td>").Append(Enc(s.Direction)).Append("</td>")
              .Append("<td>").Append(Enc(s.Direction == "Outbound" ? $"{s.Host} → {s.TargetHost}" : s.Host)).Append("</td>")
              .Append("<td>").Append(Enc(s.User is null
                  ? (s.InferredUser is null ? null : $"likely {s.InferredUser} (inferred)")
                  : s.Domain is null ? s.User : $"{s.Domain}\\{s.User}")).Append("</td>")
              .Append("<td>").Append(Enc(string.Join(" ", new[] { s.SourceIp, s.SourceHost }.Where(x => x is not null)))).Append("</td>")
              .Append("<td>").Append(Enc(s.Detail)).Append("</td>")
              .Append("<td class=\"mono\">").Append(Enc(s.Commands)).Append("</td>")
              .Append("<td>").Append(Enc(s.Confidence)).Append("</td></tr>");
        }
        sb.Append("</tbody></table>");
        Footer(sb);
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    public static void ExportFindings(IEnumerable<Finding> findings, string path, string title)
    {
        var sb = new StringBuilder();
        Header(sb, title);
        sb.Append("<table><thead><tr><th>Severity</th><th>Rule</th><th>Timestamp (UTC)</th>")
          .Append("<th>User</th><th>Source IP</th><th>Host</th><th>Count</th><th>MITRE</th><th>Description</th><th>Reasoning</th></tr></thead><tbody>");
        foreach (var f in findings)
        {
            sb.Append("<tr class=\"sev").Append((int)f.Severity).Append("\">")
              .Append("<td>").Append(Enc(f.Severity.ToString())).Append("</td>")
              .Append("<td>").Append(Enc(f.RuleName)).Append("</td>")
              .Append("<td>").Append(Enc(Ts(f.Timestamp))).Append("</td>")
              .Append("<td>").Append(Enc(f.User)).Append("</td>")
              .Append("<td>").Append(Enc(f.SourceIp)).Append("</td>")
              .Append("<td>").Append(Enc(f.Host)).Append("</td>")
              .Append("<td>").Append(f.Count).Append("</td>")
              .Append("<td>").Append(Enc(f.Mitre)).Append("</td>")
              .Append("<td>").Append(Enc(f.Description)).Append("</td>")
              .Append("<td>").Append(Enc(f.Reasoning)).Append("</td></tr>");
        }
        sb.Append("</tbody></table>");
        Footer(sb);
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static void Header(StringBuilder sb, string title)
    {
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>")
          .Append(Enc(title)).Append("</title><style>")
          .Append("body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b;}")
          .Append("h1{font-size:18px;} .meta{color:#666;font-size:12px;margin-bottom:16px;}")
          .Append("table{border-collapse:collapse;width:100%;font-size:12px;}")
          .Append("th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top;}")
          .Append(".mono{font-family:Consolas,monospace;font-size:11px;word-break:break-all;}")
          .Append("th{background:#f3f3f3;} tr.fail{background:#fdecea;} tr.priv{background:#fff6e0;} tr.rex{background:#efe7fb;}")
          .Append("tr.sev4{background:#f9d6d2;} tr.sev3{background:#fdecea;} tr.sev2{background:#fff6e0;}")
          .Append("</style></head><body><h1>").Append(Enc(title)).Append("</h1>")
          .Append("<div class=\"meta\">Generated ")
          .Append(Enc(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture)))
          .Append(" by Login Activity Triage. All times UTC.</div>");
    }

    private static void Footer(StringBuilder sb) => sb.Append("</body></html>");

    private static string Enc(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : WebUtility.HtmlEncode(value);
}
