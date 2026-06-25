using System.Globalization;
using System.Net;
using System.Text;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Export;

/// <summary>
/// Produces simple, self-contained HTML reports suitable for attaching to an
/// investigation note. No external CSS/JS; everything is inlined.
/// </summary>
public static class HtmlExporter
{
    private static readonly (string Header, Func<NormalizedEvent, string?> Value)[] Columns =
    {
        ("Timestamp",   e => e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
        ("Host",        e => e.Hostname),
        ("Event",       e => $"{e.EventId} {e.EventType}"),
        ("User",        e => e.TargetUserName),
        ("Source IP",   e => e.SourceIp),
        ("Logon Type",  e => e.LogonType is null ? null : $"{e.LogonType} {e.LogonTypeDescription}"),
        ("Auth",        e => e.AuthenticationPackage),
        ("Elevated",    e => e.ElevatedToken is null ? null : (e.ElevatedToken.Value ? "Yes" : "No")),
        ("Status",      e => e.Status),
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
            var cls = e.IsFailure ? " class=\"fail\"" : (e.IsPrivileged ? " class=\"priv\"" : "");
            sb.Append("<tr").Append(cls).Append('>');
            foreach (var c in Columns)
                sb.Append("<td>").Append(Enc(c.Value(e))).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");
        Footer(sb);
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    public static void ExportFindings(IEnumerable<Finding> findings, string path, string title)
    {
        var sb = new StringBuilder();
        Header(sb, title);
        sb.Append("<table><thead><tr><th>Severity</th><th>Rule</th><th>Timestamp</th>")
          .Append("<th>User</th><th>Source IP</th><th>Host</th><th>Description</th><th>Reasoning</th></tr></thead><tbody>");
        foreach (var f in findings)
        {
            sb.Append("<tr class=\"sev").Append((int)f.Severity).Append("\">")
              .Append("<td>").Append(Enc(f.Severity.ToString())).Append("</td>")
              .Append("<td>").Append(Enc(f.RuleName)).Append("</td>")
              .Append("<td>").Append(Enc(f.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))).Append("</td>")
              .Append("<td>").Append(Enc(f.User)).Append("</td>")
              .Append("<td>").Append(Enc(f.SourceIp)).Append("</td>")
              .Append("<td>").Append(Enc(f.Host)).Append("</td>")
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
          .Append("th{background:#f3f3f3;} tr.fail{background:#fdecea;} tr.priv{background:#fff6e0;}")
          .Append("tr.sev3,tr.sev4{background:#fdecea;} tr.sev2{background:#fff6e0;}")
          .Append("</style></head><body><h1>").Append(Enc(title)).Append("</h1>")
          .Append("<div class=\"meta\">Generated ")
          .Append(Enc(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)))
          .Append(" by Login Activity Triage GUI</div>");
    }

    private static void Footer(StringBuilder sb) => sb.Append("</body></html>");

    private static string Enc(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : WebUtility.HtmlEncode(value);
}
