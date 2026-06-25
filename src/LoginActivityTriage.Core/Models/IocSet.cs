namespace LoginActivityTriage.Core.Models;

/// <summary>
/// A set of investigator-supplied indicators of compromise (hostnames, IP
/// addresses and user names). Used to (a) visually flag matching rows in any
/// data view and (b) optionally restrict views to IOC matches only.
///
/// Matching is case-insensitive. IPs match exactly; hostnames also match on the
/// short (first-label) name so a pasted "PC01" flags "PC01.contoso.local"; user
/// names also match the bare account when events carry a "DOMAIN\user" form.
/// </summary>
public sealed class IocSet
{
    private static readonly char[] Separators = { '\r', '\n', ',', ';', ' ', '\t' };

    private readonly HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _users = new(StringComparer.OrdinalIgnoreCase);

    public int HostCount => _hosts.Count;
    public int IpCount => _ips.Count;
    public int UserCount => _users.Count;

    public bool IsEmpty => _hosts.Count == 0 && _ips.Count == 0 && _users.Count == 0;

    /// <summary>Replaces the indicator lists from free-form pasted text (any of
    /// newline / comma / semicolon / space separated).</summary>
    public void Set(string? hostsText, string? ipsText, string? usersText)
    {
        Load(_hosts, hostsText);
        Load(_ips, ipsText);
        Load(_users, usersText);
    }

    public void Clear()
    {
        _hosts.Clear();
        _ips.Clear();
        _users.Clear();
    }

    private static void Load(HashSet<string> target, string? text)
    {
        target.Clear();
        if (string.IsNullOrWhiteSpace(text)) return;
        foreach (var token in text.Split(Separators,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            target.Add(token);
    }

    /// <summary>True when the event's host, source IP or user matches any indicator.</summary>
    public bool Matches(NormalizedEvent e) =>
        MatchesHost(e.Hostname) || MatchesIp(e.SourceIp) || MatchesUser(e.TargetUserName);

    public bool MatchesIp(string? ip) =>
        _ips.Count > 0 && !string.IsNullOrWhiteSpace(ip) && _ips.Contains(ip.Trim());

    public bool MatchesHost(string? host)
    {
        if (_hosts.Count == 0 || string.IsNullOrWhiteSpace(host)) return false;
        host = host.Trim();
        if (_hosts.Contains(host)) return true;
        var shortName = host.Split('.')[0];
        return shortName.Length != host.Length && _hosts.Contains(shortName);
    }

    public bool MatchesUser(string? user)
    {
        if (_users.Count == 0 || string.IsNullOrWhiteSpace(user)) return false;
        user = user.Trim();
        if (_users.Contains(user)) return true;
        var slash = user.IndexOf('\\');
        return slash >= 0 && _users.Contains(user[(slash + 1)..]);
    }
}
