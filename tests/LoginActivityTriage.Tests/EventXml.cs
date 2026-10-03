using System.Globalization;
using System.Security;
using System.Text;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Builds event XML in the exact shape produced by EventRecord.ToXml(), so tests exercise the
/// real parser. Field names follow the Windows event manifests.
/// </summary>
internal static class EventXml
{
    public const string Security = "Microsoft-Windows-Security-Auditing";
    public const string Scm = "Service Control Manager";
    public const string LsmProvider = "Microsoft-Windows-TerminalServices-LocalSessionManager";
    public const string Rcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager";
    public const string CoreTs = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS";
    public const string WinRm = "Microsoft-Windows-WinRM";
    public const string PsClassic = "PowerShell";
    public const string PsOperational = "Microsoft-Windows-PowerShell";
    public const string Sysmon = "Microsoft-Windows-Sysmon";

    public static readonly DateTimeOffset T0 = new(2026, 6, 20, 10, 0, 0, TimeSpan.Zero);

    private static long _record = 1000;

    /// <summary>Standard &lt;EventData&gt;&lt;Data Name=..&gt; event.</summary>
    public static string Event(string provider, string channel, int id, DateTimeOffset time, string computer,
        IEnumerable<(string Name, string Value)> data, string? userSid = null)
    {
        var sb = Head(provider, channel, id, time, computer, userSid);
        sb.Append("<EventData>");
        foreach (var (n, v) in data)
            sb.Append("<Data Name='").Append(n).Append("'>").Append(SecurityElement.Escape(v)).Append("</Data>");
        sb.Append("</EventData></Event>");
        return sb.ToString();
    }

    /// <summary>Unnamed positional &lt;Data&gt; (classic providers).</summary>
    public static string Positional(string provider, string channel, int id, DateTimeOffset time, string computer,
        params string[] values)
    {
        var sb = Head(provider, channel, id, time, computer, null);
        sb.Append("<EventData>");
        foreach (var v in values) sb.Append("<Data>").Append(SecurityElement.Escape(v)).Append("</Data>");
        sb.Append("</EventData></Event>");
        return sb.ToString();
    }

    /// <summary>&lt;UserData&gt;&lt;EventXML&gt;&lt;Field&gt; form (Terminal Services, Eventlog).</summary>
    public static string UserData(string provider, string channel, int id, DateTimeOffset time, string computer,
        string wrapper, IEnumerable<(string Name, string Value)> data)
    {
        var sb = Head(provider, channel, id, time, computer, null);
        sb.Append("<UserData><").Append(wrapper).Append(" xmlns='Event_NS'>");
        foreach (var (n, v) in data)
            sb.Append('<').Append(n).Append('>').Append(SecurityElement.Escape(v)).Append("</").Append(n).Append('>');
        sb.Append("</").Append(wrapper).Append("></UserData></Event>");
        return sb.ToString();
    }

    public static string Sec(int id, DateTimeOffset time, string computer, params (string, string)[] data) =>
        Event(Security, "Security", id, time, computer, data);

    private static StringBuilder Head(string provider, string channel, int id, DateTimeOffset time, string computer, string? sid)
    {
        var sb = new StringBuilder("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>");
        sb.Append("<Provider Name='").Append(provider).Append("'/>")
          .Append("<EventID>").Append(id).Append("</EventID>")
          .Append("<TimeCreated SystemTime='").Append(time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture)).Append("'/>")
          .Append("<EventRecordID>").Append(Interlocked.Increment(ref _record)).Append("</EventRecordID>")
          .Append("<Channel>").Append(channel).Append("</Channel>")
          .Append("<Computer>").Append(computer).Append("</Computer>");
        if (sid is not null) sb.Append("<Security UserID='").Append(sid).Append("'/>");
        else sb.Append("<Security/>");
        sb.Append("</System>");
        return sb;
    }

    // ---- common Security events ----

    public static string Logon(DateTimeOffset t, string host, string user, string domain, int type, string? ip,
        string logonId, string auth = "NTLM", string? workstation = null, string elevated = "%%1843",
        string logonProcess = "NtLmSsp") =>
        Sec(4624, t, host,
            ("SubjectUserSid", "S-1-0-0"), ("SubjectUserName", "-"), ("SubjectDomainName", "-"), ("SubjectLogonId", "0x0"),
            ("TargetUserSid", "S-1-5-21-1-2-3-1105"), ("TargetUserName", user), ("TargetDomainName", domain),
            ("TargetLogonId", logonId), ("LogonType", type.ToString(CultureInfo.InvariantCulture)),
            ("LogonProcessName", logonProcess), ("AuthenticationPackageName", auth),
            ("WorkstationName", workstation ?? "-"), ("IpAddress", ip ?? "-"), ("IpPort", "49812"),
            ("ElevatedToken", elevated), ("TargetLinkedLogonId", "0x0"));

    public static string Logoff(DateTimeOffset t, string host, string user, string logonId, int type = 3) =>
        Sec(4634, t, host, ("TargetUserSid", "S-1-5-21-1-2-3-1105"), ("TargetUserName", user),
            ("TargetDomainName", "CONTOSO"), ("TargetLogonId", logonId), ("LogonType", type.ToString(CultureInfo.InvariantCulture)));

    public static string Failed(DateTimeOffset t, string host, string user, string ip, int type = 3) =>
        Sec(4625, t, host, ("TargetUserName", user), ("TargetDomainName", "CONTOSO"),
            ("Status", "0xc000006d"), ("SubStatus", "0xc000006a"), ("LogonType", type.ToString(CultureInfo.InvariantCulture)),
            ("AuthenticationPackageName", "NTLM"), ("IpAddress", ip), ("IpPort", "51515"), ("WorkstationName", "ATTACKER"));

    public static string Process(DateTimeOffset t, string host, string image, string parent, string cmd,
        string subjectUser = "SYSTEM", string subjectLogonId = "0x3e7", string targetLogonId = "0x0") =>
        Sec(4688, t, host, ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", subjectUser), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", subjectLogonId), ("NewProcessId", "0x1a2c"), ("NewProcessName", image),
            ("TokenElevationType", "%%1936"), ("ProcessId", "0x2b0"), ("CommandLine", cmd),
            ("TargetUserSid", "S-1-0-0"), ("TargetUserName", "-"), ("TargetDomainName", "-"), ("TargetLogonId", targetLogonId),
            ("ParentProcessName", parent), ("MandatoryLabel", "S-1-16-16384"));

    public static string Share(int id, DateTimeOffset t, string host, string user, string ip, string share,
        string? relative, string logonId, string accessMask = "0x2") =>
        Sec(id, t, host, ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", user), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", logonId), ("ObjectType", "File"), ("IpAddress", ip), ("IpPort", "50111"),
            ("ShareName", share), ("ShareLocalPath", "\\??\\C:\\Windows"), ("RelativeTargetName", relative ?? ""),
            ("AccessMask", accessMask), ("AccessList", "%%4417"));

    public static string ServiceInstall(DateTimeOffset t, string host, string name, string image, string sid = "S-1-5-21-1-2-3-500") =>
        Event(Scm, "System", 7045, t, host, new[]
        {
            ("ServiceName", name), ("ImagePath", image), ("ServiceType", "user mode service"),
            ("StartType", "demand start"), ("AccountName", "LocalSystem"),
        }, sid);

    public static string Lsm(int id, DateTimeOffset t, string host, string user, string sessionId, string? address)
    {
        var data = new List<(string, string)> { ("User", user), ("SessionID", sessionId) };
        if (address is not null) data.Add(("Address", address));
        return UserData(LsmProvider, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", id, t, host, "EventXML", data);
    }
}
