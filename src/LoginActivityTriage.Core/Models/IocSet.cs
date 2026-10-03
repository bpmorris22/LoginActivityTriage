using LoginActivityTriage.Core.Mapping;

namespace LoginActivityTriage.Core.Models;

/// <summary>
/// A set of investigator-supplied indicators of compromise (hostnames, IP
/// addresses and user names). Used to (a) visually flag matching rows in any
/// data view and (b) optionally restrict views to IOC matches only.
///
/// Matching is case-insensitive. IPs match exactly; hostnames also match on the
/// short (first-label) name so a pasted "PC01" flags "PC01.contoso.local"; user
/// names also match the bare account when events carry "DOMAIN\user" or "user@realm".
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
        Load(_hosts, hostsText, HostKey.Of);
        Load(_ips, ipsText, s => s);
        Load(_users, usersText, s => s);
    }

    public void Clear()
    {
        _hosts.Clear();
        _ips.Clear();
        _users.Clear();
    }

    private static void Load(HashSet<string> target, string? text, Func<string, string> extra)
    {
        target.Clear();
        if (string.IsNullOrWhiteSpace(text)) return;
        foreach (var token in text.Split(Separators,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            target.Add(token);
            var alt = extra(token);
            if (!string.IsNullOrEmpty(alt)) target.Add(alt);
        }
    }

    /// <summary>
    /// True when the event's host (recording host, source workstation or remote target),
    /// source IP or user (target or acting subject) matches any indicator.
    /// </summary>
    public bool Matches(NormalizedEvent e) =>
        MatchesHost(e.Hostname) || MatchesHost(e.WorkstationName) || MatchesHost(e.TargetServer) ||
        MatchesIp(e.SourceIp) || MatchesUser(e.TargetUserName) || MatchesUser(e.SubjectUserName);

    /// <summary>True when a stitched remote session touches any indicator.</summary>
    public bool Matches(RemoteSession s) =>
        MatchesHost(s.Host) || MatchesHost(s.SourceHost) || MatchesHost(s.TargetHost) || MatchesHost(s.TargetHostName) ||
        MatchesIp(s.SourceIp) || MatchesIp(s.TargetHost) || MatchesUser(s.User) || MatchesUser(s.CredentialsUsed);

    public bool MatchesIp(string? ip)
    {
        if (_ips.Count == 0 || string.IsNullOrWhiteSpace(ip)) return false;
        // A session may carry several "ip1; ip2" values.
        foreach (var part in ip.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (_ips.Contains(part)) return true;
        return false;
    }

    public bool MatchesHost(string? host)
    {
        if (_hosts.Count == 0 || string.IsNullOrWhiteSpace(host)) return false;
        host = host.Trim();
        if (_hosts.Contains(host)) return true;
        var shortName = HostKey.Of(host);
        return shortName.Length > 0 && _hosts.Contains(shortName);
    }

    public bool MatchesUser(string? user)
    {
        if (_users.Count == 0 || string.IsNullOrWhiteSpace(user)) return false;
        user = user.Trim();
        return _users.Contains(user) || _users.Contains(UserKey.Bare(user));
    }
}
