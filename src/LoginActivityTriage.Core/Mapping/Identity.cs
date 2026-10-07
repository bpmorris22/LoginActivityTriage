using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace LoginActivityTriage.Core.Mapping;

/// <summary>Well-known remote-access technique labels used on events and sessions.</summary>
public static class RemoteTechnique
{
    public const string Rdp = "RDP";
    public const string PsExec = "PsExec";
    public const string PsRemoting = "PS Remoting";
    public const string WinRs = "WinRS";
    public const string Wmi = "WMI";
    public const string Dcom = "DCOM";
    public const string ScheduledTask = "Scheduled task";
    public const string ServiceInstall = "Service install";
    public const string RemoteServiceControl = "Remote service control";
    public const string AdminShare = "SMB admin share";
    /// <summary>Outbound SMB with explicit credentials (4648 with a cifs/ SPN): file or admin shares on another host.</summary>
    public const string Smb = "SMB";
    public const string LogCleared = "Log cleared";
    public const string Ssh = "SSH";
    /// <summary>Third-party remote access / RMM software (AnyDesk, TeamViewer, Splashtop, ScreenConnect...).</summary>
    public const string RemoteAccessTool = "Remote access tool";
}

/// <summary>
/// What an event means for the host's session / power timeline, independent of technique: shown
/// as a label in the timeline (events.csv "Activity").
/// </summary>
public static class EventActivity
{
    public const string Logon = "Logon";
    public const string LogonFailed = "Logon failed";
    public const string Logoff = "Logoff";
    public const string Disconnect = "Disconnect";
    public const string Reconnect = "Reconnect";
    public const string Boot = "Boot";
    public const string Shutdown = "Shutdown";
    public const string Restart = "Restart";
    /// <summary>Restart or power-off whose type the event did not state in a recognisable language.</summary>
    public const string ShutdownOrRestart = "Shutdown / restart";
    public const string UnexpectedShutdown = "Unexpected shutdown";
}

/// <summary>Time-zone helpers: fixed-offset zones and parsing of investigator input.</summary>
public static class TimeZoneUtil
{
    private static readonly System.Text.RegularExpressions.Regex Offset =
        new(@"^(UTC|GMT)?\s*(?<s>[+-])(?<h>\d{1,2})(:?(?<m>\d{2}))?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>A fixed-offset zone such as "UTC+08:00".</summary>
    public static TimeZoneInfo FixedOffset(int offsetMinutes, string? note = null)
    {
        var sign = offsetMinutes < 0 ? "-" : "+";
        var abs = Math.Abs(offsetMinutes);
        var id = $"UTC{sign}{abs / 60:00}:{abs % 60:00}";
        var name = note is null ? id : $"{id} ({note})";
        return TimeZoneInfo.CreateCustomTimeZone(id, TimeSpan.FromMinutes(offsetMinutes), name, name);
    }

    /// <summary>
    /// Parses "utc", "local", a Windows id ("Taipei Standard Time"), an IANA id ("Asia/Taipei")
    /// or a fixed offset ("UTC+08:00", "+8", "-05:30"). Throws ArgumentException when unknown.
    /// </summary>
    public static TimeZoneInfo Parse(string id)
    {
        var t = id.Trim();
        if (t.Equals("local", StringComparison.OrdinalIgnoreCase)) return TimeZoneInfo.Local;
        if (t.Equals("utc", StringComparison.OrdinalIgnoreCase) || t.Equals("gmt", StringComparison.OrdinalIgnoreCase)) return TimeZoneInfo.Utc;
        var m = Offset.Match(t);
        if (m.Success)
        {
            var minutes = int.Parse(m.Groups["h"].Value) * 60 + (m.Groups["m"].Success ? int.Parse(m.Groups["m"].Value) : 0);
            if (minutes > 14 * 60) throw new ArgumentException($"Offset out of range: {id}");
            return FixedOffset(m.Groups["s"].Value == "-" ? -minutes : minutes);
        }
        try { return TimeZoneInfo.FindSystemTimeZoneById(t); }
        catch (Exception) { throw new ArgumentException($"Unknown time zone '{id}'."); }
    }
}

/// <summary>
/// Classifies accounts that generate the bulk of authentication noise and are
/// almost never the subject of a triage question on their own.
/// </summary>
public static class AccountClassifier
{
    private static readonly HashSet<string> NoiseNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "LOCAL SYSTEM",
        "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE",
        "NT AUTHORITY\\ANONYMOUS LOGON",
    };

    private static readonly Regex DesktopWindowManager = new(@"^(DWM|UMFD)-\d+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>True for machine ($), SYSTEM / service, anonymous, DWM and UMFD accounts.</summary>
    public static bool IsNoise(string? user, string? sid = null)
    {
        // The NULL SID (S-1-0-0) only means "no SID recorded": failed logons (4625) carry it for real
        // accounts, so it marks noise only when there is no name either.
        if (IsWellKnownServiceSid(sid) && !(sid!.Trim() == "S-1-0-0" && !string.IsNullOrWhiteSpace(user) && user.Trim() != "-"))
            return true;
        if (string.IsNullOrWhiteSpace(user)) return false;
        var bare = UserKey.Bare(user);
        return bare.EndsWith('$') || NoiseNames.Contains(user.Trim()) || NoiseNames.Contains(bare) ||
               DesktopWindowManager.IsMatch(bare);
    }

    /// <summary>True for SYSTEM / LOCAL SERVICE / NETWORK SERVICE / anonymous / DWM / UMFD SIDs.</summary>
    public static bool IsWellKnownServiceSid(string? sid)
    {
        if (string.IsNullOrWhiteSpace(sid)) return false;
        var s = sid.Trim();
        return s is "S-1-5-18" or "S-1-5-19" or "S-1-5-20" or "S-1-5-7" or "S-1-0-0" ||
               s.StartsWith("S-1-5-90-", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("S-1-5-96-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Display name for a well-known service SID ("S-1-5-18" → "SYSTEM"), or null.</summary>
    public static string? WellKnownSidName(string? sid) => sid?.Trim() switch
    {
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "LOCAL SERVICE",
        "S-1-5-20" => "NETWORK SERVICE",
        "S-1-5-7" => "ANONYMOUS LOGON",
        _ => null,
    };

    public static bool IsAnonymous(string? user, string? sid) =>
        string.Equals(sid?.Trim(), "S-1-5-7", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(UserKey.Bare(user), "ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase);

    private static readonly string[] PrivilegedGroupFragments =
    {
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
        "Backup Operators", "Server Operators", "Print Operators", "DnsAdmins", "Group Policy Creator Owners",
        "Remote Desktop Users", "Remote Management Users", "Hyper-V Administrators", "Enterprise Key Admins",
        "Key Admins", "Cert Publishers", "Distributed COM Users",
    };

    /// <summary>True when a group name grants admin or remote-access rights.</summary>
    public static bool IsPrivilegedGroup(string? group) =>
        !string.IsNullOrWhiteSpace(group) &&
        PrivilegedGroupFragments.Any(g => group.Contains(g, StringComparison.OrdinalIgnoreCase));
}

/// <summary>Normalises user names so the same person joins across logs.</summary>
public static class UserKey
{
    /// <summary>Strips a DOMAIN\ prefix or an @realm suffix: "CONTOSO\jdoe" / "jdoe@contoso.local" → "jdoe".</summary>
    public static string Bare(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return string.Empty;
        var u = user.Trim();
        var slash = u.LastIndexOf('\\');
        if (slash >= 0) u = u[(slash + 1)..];
        var at = u.IndexOf('@');
        if (at > 0) u = u[..at];
        return u;
    }

    /// <summary>Splits "DOMAIN\user" or "user@realm" into (user, domain). Domain is null when absent.</summary>
    public static (string? User, string? Domain) Split(string? user)
    {
        if (string.IsNullOrWhiteSpace(user)) return (null, null);
        var u = user.Trim();
        var slash = u.IndexOf('\\');
        if (slash >= 0) return (NullIfEmpty(u[(slash + 1)..]), NullIfEmpty(u[..slash]));
        var at = u.IndexOf('@');
        if (at > 0) return (NullIfEmpty(u[..at]), NullIfEmpty(u[(at + 1)..]));
        return (u, null);
    }

    /// <summary>Case-insensitive equality on the bare user name.</summary>
    public static bool Same(string? a, string? b)
    {
        var x = Bare(a);
        var y = Bare(b);
        return x.Length > 0 && string.Equals(x, y, StringComparison.OrdinalIgnoreCase);
    }

    private static string? NullIfEmpty(string s) => string.IsNullOrWhiteSpace(s) ? null : s;
}

/// <summary>
/// Domain-aware account identity. The bare name alone ("administrator") is a display key, not an
/// identity: CONTOSO\administrator, SERVER01\administrator (local) and OTHER\administrator are
/// different accounts. Two references can be the same account when the bare names match and the
/// domains match - or one of them does not say (many events omit the domain).
/// </summary>
public static class AccountKey
{
    /// <summary>Comparable domain: NetBIOS form / first DNS label, upper-case; null when absent or a placeholder.</summary>
    public static string? Domain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return null;
        var d = domain.Trim();
        if (d is "-" or "." || d.Equals("WORKGROUP", StringComparison.OrdinalIgnoreCase)) return null;
        var dot = d.IndexOf('.');
        if (dot > 0) d = d[..dot];
        return d.ToUpperInvariant();
    }

    /// <summary>
    /// The domain of an account reference: the explicit domain, else the DOMAIN\ or @realm part of
    /// the name. Null for a SID-named account (group members logged as S-1-5-21-...): the SID is
    /// already the identity, and the domain logged beside it is the group's, not the account's.
    /// </summary>
    public static string? DomainOf(string? user, string? domain) =>
        UserKey.Bare(user).StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ? null
            : Domain(domain) ?? Domain(UserKey.Split(user).Domain);

    /// <summary>True when the two references can be the same account (see the class remarks).</summary>
    public static bool SameAccount(string? userA, string? domainA, string? userB, string? domainB)
    {
        if (!UserKey.Same(userA, userB)) return false;
        var a = DomainOf(userA, domainA);
        var b = DomainOf(userB, domainB);
        return a is null || b is null || a == b;
    }

    /// <summary>"DOMAIN\user" when the domain is known, else the bare name.</summary>
    public static string Of(string? user, string? domain)
    {
        var bare = UserKey.Bare(user);
        var d = DomainOf(user, domain);
        return d is null ? bare : $"{d}\\{bare}";
    }
}

/// <summary>Normalises host names so FQDN and NetBIOS forms join.</summary>
public static class HostKey
{
    /// <summary>Upper-case first DNS label: "host01.contoso.local" → "HOST01". Strips leading \\ and trailing $.</summary>
    public static string Of(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return string.Empty;
        var h = host.Trim().TrimStart('\\').TrimEnd('$');
        if (IPAddress.TryParse(h, out _)) return h;
        var dot = h.IndexOf('.');
        if (dot > 0) h = h[..dot];
        return h.ToUpperInvariant();
    }

    public static bool Same(string? a, string? b)
    {
        var x = Of(a);
        return x.Length > 0 && x == Of(b);
    }

    /// <summary>True when the name refers to the local machine (localhost, 127.0.0.1, ::1 or the same host).</summary>
    public static bool IsLocal(string? target, string? self) =>
        string.IsNullOrWhiteSpace(target) ||
        target.Trim() is "localhost" or "127.0.0.1" or "::1" or "." ||
        Same(target, self);
}

/// <summary>IP helpers: normalisation, local checks and CIDR matching.</summary>
public static class IpUtil
{
    /// <summary>Trims, maps "-" to null, strips "::ffff:" and a trailing ":port" from IPv4.</summary>
    public static string? Normalize(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        var t = ip.Trim();
        if (t is "-" or "LOCAL") return t == "LOCAL" ? "LOCAL" : null;
        if (t.StartsWith("::ffff:", StringComparison.OrdinalIgnoreCase)) t = t[7..];
        // "10.1.2.3:51234" (RdpCoreTS 131) → "10.1.2.3"
        var colon = t.IndexOf(':');
        if (colon > 0 && t.IndexOf(':', colon + 1) < 0 && IPAddress.TryParse(t[..colon], out _)) t = t[..colon];
        // "[fe80::1]:3389"
        if (t.StartsWith('[') && t.Contains(']')) t = t[1..t.IndexOf(']')];
        return t;
    }

    /// <summary>Port from "ip:port", or null.</summary>
    public static string? PortOf(string? ipWithPort)
    {
        if (string.IsNullOrWhiteSpace(ipWithPort)) return null;
        var t = ipWithPort.Trim();
        var colon = t.LastIndexOf(':');
        if (colon <= 0 || t.IndexOf(':') != colon) return null;
        var port = t[(colon + 1)..];
        return port.All(char.IsDigit) && port.Length > 0 ? port : null;
    }

    public static bool IsLocalOrBlank(string? ip) =>
        string.IsNullOrWhiteSpace(ip) ||
        ip.Trim() is "-" or "::1" or "127.0.0.1" or "0.0.0.0" or "LOCAL" or "::";

    /// <summary>
    /// True when the text is a complete IPv4 dotted quad or an IPv6 address. (IPAddress.TryParse
    /// alone accepts shorthand such as "16.9" = 16.0.0.9, which would turn partial filters into
    /// exact matches.)
    /// </summary>
    public static bool IsIp(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        var t = text.Trim();
        if (!IPAddress.TryParse(t, out var a)) return false;
        return a.AddressFamily == AddressFamily.InterNetworkV6 ? t.Contains(':') : t.Count(c => c == '.') == 3;
    }

    /// <summary>
    /// Investigator IP filter: "10.0.0.0/8" = CIDR, "10.0.*" = prefix, a full address = exact,
    /// anything else = case-insensitive substring.
    /// </summary>
    public static bool MatchesFilter(string? ip, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return true;
        if (string.IsNullOrWhiteSpace(ip)) return false;
        var f = filter.Trim();
        var v = ip.Trim();
        if (f.Contains('/')) return InCidr(v, f);
        if (f.EndsWith('*')) return v.StartsWith(f.TrimEnd('*'), StringComparison.OrdinalIgnoreCase);
        if (IsIp(f)) return string.Equals(v, f, StringComparison.OrdinalIgnoreCase);
        return v.Contains(f, StringComparison.OrdinalIgnoreCase);
    }

    public static bool InCidr(string ip, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var net) ||
            !int.TryParse(parts[1], out var bits) || !IPAddress.TryParse(ip, out var addr))
            return false;
        if (net.AddressFamily != addr.AddressFamily) return false;
        var a = addr.GetAddressBytes();
        var n = net.GetAddressBytes();
        if (bits < 0 || bits > a.Length * 8) return false;
        for (var i = 0; i < a.Length && bits > 0; i++, bits -= 8)
        {
            var mask = bits >= 8 ? 0xFF : (byte)(0xFF << (8 - bits));
            if ((a[i] & mask) != (n[i] & mask)) return false;
        }
        return true;
    }

    /// <summary>
    /// True for a routable internet address: a valid IP that is not private, loopback, link-local,
    /// unspecified (0.0.0.0 / ::), carrier-grade NAT (100.64/10), benchmarking or multicast.
    /// </summary>
    public static bool IsPublic(string? ip)
    {
        if (!IsIp(ip) || IsLocalOrBlank(ip) || IsPrivate(ip)) return false;
        var a = IPAddress.Parse(ip!.Trim());
        if (a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(a)) return false;
        if (a.AddressFamily == AddressFamily.InterNetworkV6) return !a.IsIPv6Multicast && !a.IsIPv6LinkLocal;
        var b = a.GetAddressBytes();
        return b[0] != 0 && !(b[0] == 100 && b[1] >= 64 && b[1] <= 127) && b[0] < 224 &&
               !(b[0] == 198 && (b[1] == 18 || b[1] == 19));
    }

    /// <summary>True for RFC1918 / link-local / loopback / ULA addresses.</summary>
    public static bool IsPrivate(string? ip)
    {
        if (!IPAddress.TryParse(ip?.Trim(), out var a)) return false;
        if (IPAddress.IsLoopback(a)) return true;
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || (a.GetAddressBytes()[0] & 0xFE) == 0xFC;
        var b = a.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) ||
               (b[0] == 169 && b[1] == 254);
    }
}
