using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Analytics;

/// <summary>Aggregated activity grouped by source IP.</summary>
public sealed class SourceIpPivot
{
    public string SourceIp { get; init; } = "";
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int UniqueUsers { get; init; }
    public int UniqueHosts { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    public int Rdp { get; init; }
    public int RemoteExec { get; init; }
    public int Explicit { get; init; }
    public int Privileged { get; init; }
    public bool IsPrivateAddress { get; init; }
    public int SuspicionScore { get; init; }
    public string? Users { get; init; }
    public string? Hosts { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>Aggregated activity grouped by user.</summary>
public sealed class UserPivot
{
    public string User { get; init; } = "";
    /// <summary>The account's SID(s) as logged, most frequent first ("; "-separated; several when a
    /// bare name covers accounts of different hosts). The NULL SID of failed logons is left out.</summary>
    public string? Sid { get; init; }
    /// <summary>Machine, SYSTEM / service, DWM / UMFD or anonymous account (scored 0).</summary>
    public bool IsSystemAccount { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int HostCount { get; init; }
    public int SourceIpCount { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    public int Rdp { get; init; }
    public int RemoteExec { get; init; }
    /// <summary>Third-party remote access / RMM software installed or started under this account.</summary>
    public int RemoteAccessTool { get; init; }
    /// <summary>4648s in which this account supplied another account's credentials.</summary>
    public int UsedOthersCreds { get; init; }
    /// <summary>4648s in which another account supplied this account's credentials.</summary>
    public int CredsUsedByOthers { get; init; }
    public int Privileged { get; init; }
    public int GroupChanges { get; init; }
    public int SuspicionScore { get; init; }
    public string? Hosts { get; init; }
    public string? SourceIps { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>Aggregated activity grouped by the host whose logs recorded it.</summary>
public sealed class HostPivot
{
    public string Host { get; init; } = "";
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int Users { get; init; }
    public int SourceIps { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    /// <summary>Inbound RDP evidence (this host was accessed).</summary>
    public int Rdp { get; init; }
    /// <summary>This host's own RDP client use (connections to other hosts).</summary>
    public int RdpOutbound { get; init; }
    public int RemoteExec { get; init; }
    /// <summary>Third-party remote access / RMM software installed or started on this host.</summary>
    public int RemoteAccessTool { get; init; }
    public int ServiceInstalls { get; init; }
    public int Privileged { get; init; }
    public int LogClears { get; init; }
    /// <summary>UTC offset from the host's System 6013 events, when present.</summary>
    public string? TimeZone { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>
/// Aggregated activity per remote system that a collected host connected to: outbound sessions
/// (RDP, PsExec, WinRM, WMI...) and explicit-credential hand-offs (4648) naming it. An address and
/// the name another event resolves it to (10.10.20.33 / SQL01.contoso.local) are one row.
/// </summary>
public sealed class RemoteHostPivot
{
    /// <summary>The destination as logged, preferring the address when one is known.</summary>
    public string RemoteHost { get; init; } = "";
    /// <summary>Name(s) the destination resolves to (4648 target server), when different.</summary>
    public string? Name { get; init; }
    /// <summary>True when this system's own logs are part of the evidence.</summary>
    public bool IsCollected { get; init; }
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    /// <summary>Outbound sessions / connection attempts to it.</summary>
    public int Connections { get; init; }
    public int Rdp { get; init; }
    /// <summary>Outbound PsExec / WinRM / WMI / task / service sessions to it.</summary>
    public int RemoteExec { get; init; }
    /// <summary>4648 credential hand-offs naming it.</summary>
    public int ExplicitCreds { get; init; }
    public string? Techniques { get; init; }
    /// <summary>Collected hosts that connected to it (host keys, "; " separated).</summary>
    public string? FromHosts { get; init; }
    /// <summary>Accounts recorded making the connections.</summary>
    public string? Users { get; init; }
    /// <summary>Accounts inferred for connections that recorded none (see <see cref="RemoteSession.InferredUser"/>).</summary>
    public string? InferredUsers { get; init; }
    public string? CredentialsUsed { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>
/// Builds the pivot projections (and a simple suspicion score) from events.
/// Counting rules: "Successful" counts logons (<see cref="NormalizedEvent.CountsAsLogonSuccess"/>),
/// "Failed" counts authentication failures, "Rdp" counts INBOUND RDP evidence only, "RemoteExec"
/// counts inbound remote execution (third-party remote access tools are counted separately).
/// </summary>
public static class PivotBuilder
{
    private static bool IsRemoteExec(NormalizedEvent e) =>
        e.Technique is not null && e.Technique is not (RemoteTechnique.Rdp or RemoteTechnique.LogCleared or RemoteTechnique.RemoteAccessTool) &&
        !e.IsOutbound;

    private static bool IsRemoteAccessTool(NormalizedEvent e) => e.Technique == RemoteTechnique.RemoteAccessTool;

    /// <summary>A 4648 in which one real account supplied a different account's credentials (domain-aware).</summary>
    private static bool IsAltCreds(NormalizedEvent e) =>
        e.EventId == 4648 && !string.IsNullOrWhiteSpace(e.SubjectUserName) && !AccountClassifier.IsNoise(e.SubjectUserName) &&
        !string.IsNullOrWhiteSpace(e.TargetUserName) &&
        !AccountKey.SameAccount(e.SubjectUserName, e.SubjectDomain, e.TargetUserName, e.TargetDomain);

    /// <summary>
    /// Row key for the user pivot: the bare name when every reference to it names the same domain
    /// (or none), "DOMAIN\user" when the name is used by accounts of different domains (local
    /// Administrator on several hosts, two forests...). References without a domain to an ambiguous
    /// name stay on the bare row - they are not guessed into one of the accounts. System accounts
    /// are never split.
    /// </summary>
    private static Func<string?, string?, string> UserRowKey(IEnumerable<(string? User, string? Domain)> refs)
    {
        var domains = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (u, d) in refs)
        {
            var dom = AccountKey.DomainOf(u, d);
            if (dom is null || AccountClassifier.IsNoise(u)) continue;
            var bare = UserKey.Bare(u);
            if (!domains.TryGetValue(bare, out var set)) domains[bare] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(dom);
        }
        return (u, d) =>
        {
            var bare = UserKey.Bare(u);
            var dom = AccountKey.DomainOf(u, d);
            return dom is not null && domains.TryGetValue(bare, out var set) && set.Count > 1 ? $"{dom}\\{bare}" : bare;
        };
    }

    public static IEnumerable<SourceIpPivot> BySourceIp(IEnumerable<NormalizedEvent> events, IocSet? iocs = null) =>
        events.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp))
            .GroupBy(e => e.SourceIp!, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                int failed = g.Count(e => e.IsFailure);
                int hosts = Distinct(g, e => HostKey.Of(e.Hostname));
                int rdp = g.Count(e => e.IsInboundRdp);
                int priv = PrivilegedLogons(g);
                int expl = g.Count(e => e.EventId == 4648);
                int rex = g.Count(IsRemoteExec);
                return new SourceIpPivot
                {
                    SourceIp = g.Key,
                    FirstSeen = g.Min(e => e.Timestamp),
                    LastSeen = g.Max(e => e.Timestamp),
                    UniqueUsers = Distinct(g, e => UserKey.Bare(e.TargetUserName)),
                    UniqueHosts = hosts,
                    Successful = g.Count(e => e.CountsAsLogonSuccess),
                    Failed = failed,
                    Rdp = rdp,
                    RemoteExec = rex,
                    Explicit = expl,
                    Privileged = priv,
                    IsPrivateAddress = IpUtil.IsPrivate(g.Key),
                    // Public addresses get a bump: remote access from the internet is rarer and riskier.
                    SuspicionScore = Math.Min(100, Score(failed, hosts, rdp, priv, expl, rex) +
                                                   (IpUtil.IsPublic(g.Key) ? 10 : 0)),
                    Users = Top(g, e => UserKey.Bare(e.TargetUserName)),
                    Hosts = Top(g, e => HostKey.Of(e.Hostname)),
                    IsIoc = iocs?.MatchesIp(g.Key) ?? false,
                };
            })
            .OrderByDescending(p => p.SuspicionScore).ThenByDescending(p => p.Failed);

    public static IEnumerable<UserPivot> ByUser(IEnumerable<NormalizedEvent> events, IocSet? iocs = null)
    {
        var list = events as IReadOnlyCollection<NormalizedEvent> ?? events.ToList();
        var targets = list.Where(e => !string.IsNullOrWhiteSpace(e.TargetUserName)).ToList();
        var actors = list.Where(IsAltCreds).ToList();
        var rowKey = UserRowKey(targets.Select(e => (e.TargetUserName, e.TargetDomain))
            .Concat(actors.Select(e => (e.SubjectUserName, e.SubjectDomain))));
        // An event belongs to the account it is about. A 4648 hand-off also belongs to the account
        // that supplied someone else's credentials, so both sides of it are visible and scored.
        var asTarget = targets.ToLookup(e => rowKey(e.TargetUserName, e.TargetDomain), StringComparer.OrdinalIgnoreCase);
        var asActor = actors.ToLookup(e => rowKey(e.SubjectUserName, e.SubjectDomain), StringComparer.OrdinalIgnoreCase);
        return asTarget.Select(g => g.Key).Concat(asActor.Select(g => g.Key))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(user =>
            {
                var g = asTarget[user].ToList();
                var all = g.Concat(asActor[user]).ToList();
                int failed = g.Count(e => e.IsFailure);
                int hosts = Distinct(all, e => HostKey.Of(e.Hostname));
                int rdp = g.Count(e => e.IsInboundRdp);
                int priv = PrivilegedLogons(g);
                int usedOthers = asActor[user].Count();
                int byOthers = g.Count(IsAltCreds);
                int rex = g.Count(IsRemoteExec);
                int rat = g.Count(IsRemoteAccessTool);
                var system = g.Count > 0 ? g.All(e => e.IsNoiseAccount) : AccountClassifier.IsNoise(user);
                return new UserPivot
                {
                    User = user,
                    Sid = Top(g, e => e.Sid is null || e.Sid.Trim() == "S-1-0-0" ? null : e.Sid.Trim()),
                    IsSystemAccount = system,
                    FirstSeen = all.Min(e => e.Timestamp),
                    LastSeen = all.Max(e => e.Timestamp),
                    HostCount = hosts,
                    SourceIpCount = Distinct(g.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp)), e => e.SourceIp),
                    Successful = g.Count(e => e.CountsAsLogonSuccess),
                    Failed = failed,
                    Rdp = rdp,
                    RemoteExec = rex,
                    RemoteAccessTool = rat,
                    UsedOthersCreds = usedOthers,
                    CredsUsedByOthers = byOthers,
                    Privileged = priv,
                    GroupChanges = g.Count(e => e.EventId is 4728 or 4732 or 4756),
                    // System / machine accounts are listed but not ranked as suspicious.
                    SuspicionScore = system ? 0 : Score(failed, hosts, rdp, priv, usedOthers + byOthers, rex, rat),
                    Hosts = Top(all, e => HostKey.Of(e.Hostname)),
                    SourceIps = Top(g.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp)), e => e.SourceIp),
                    IsIoc = iocs?.MatchesUser(user) ?? false,
                };
            })
            .OrderByDescending(p => p.SuspicionScore).ThenBy(p => p.IsSystemAccount).ThenByDescending(p => p.Failed);
    }

    public static IEnumerable<HostPivot> ByHost(IEnumerable<NormalizedEvent> events, IocSet? iocs = null)
    {
        var list = events as IReadOnlyCollection<NormalizedEvent> ?? events.ToList();
        var zones = HostTimeZones.FromEvents(list);
        return list.Where(e => !string.IsNullOrWhiteSpace(e.Hostname))
            .GroupBy(e => HostKey.Of(e.Hostname), StringComparer.OrdinalIgnoreCase)
            .Select(g => new HostPivot
            {
                Host = g.Key,
                FirstSeen = g.Min(e => e.Timestamp),
                LastSeen = g.Max(e => e.Timestamp),
                Users = Distinct(g.Where(e => !e.IsNoiseAccount), e => UserKey.Bare(e.TargetUserName)),
                SourceIps = Distinct(g.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp)), e => e.SourceIp),
                Successful = g.Count(e => e.CountsAsLogonSuccess),
                Failed = g.Count(e => e.IsFailure),
                Rdp = g.Count(e => e.IsInboundRdp),
                RdpOutbound = g.Count(e => e.IsRdp && e.IsOutbound),
                RemoteExec = g.Count(IsRemoteExec),
                RemoteAccessTool = g.Count(IsRemoteAccessTool),
                ServiceInstalls = g.Count(e => e.EventId is 7045 or 4697),
                Privileged = PrivilegedLogons(g),
                LogClears = g.Count(e => e.Technique == RemoteTechnique.LogCleared),
                TimeZone = zones.TryGetValue(g.Key, out var z) ? z.Id : null,
                IsIoc = iocs?.MatchesHost(g.Key) ?? false,
            })
            .OrderByDescending(p => p.RemoteExec + p.RemoteAccessTool + p.LogClears * 10).ThenByDescending(p => p.Successful + p.Failed);
    }

    /// <summary>One row per remote destination (see <see cref="RemoteHostPivot"/>).</summary>
    public static IEnumerable<RemoteHostPivot> ByRemoteHost(IEnumerable<NormalizedEvent> events, IEnumerable<RemoteSession> sessions,
        IocSet? iocs = null)
    {
        var list = events as IReadOnlyCollection<NormalizedEvent> ?? events.ToList();
        var outbound = sessions.Where(s => s.Direction == "Outbound" && (s.TargetHost ?? s.TargetHostName) is not null).ToList();
        var handoffs = list.Where(e => e.EventId == 4648 && e.TargetServer is not null && !HostKey.IsLocal(e.TargetServer, e.Hostname) &&
                                       !AccountClassifier.IsNoise(e.SubjectUserName)).ToList();
        var collected = new HashSet<string>(list.Select(e => HostKey.Of(e.Hostname)).Where(h => h.Length > 0), StringComparer.OrdinalIgnoreCase);

        // A name that a session resolved for an address (TargetHostName) joins that address's row.
        var alias = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in outbound.Where(s => s.TargetHost is not null && s.TargetHostName is not null))
            alias.TryAdd(HostKey.Of(s.TargetHostName), HostKey.Of(s.TargetHost));
        string Key(string? h) => alias.TryGetValue(HostKey.Of(h), out var a) ? a : HostKey.Of(h);

        var bySession = outbound.ToLookup(s => Key(s.TargetHost ?? s.TargetHostName), StringComparer.OrdinalIgnoreCase);
        var byHandoff = handoffs.ToLookup(e => Key(e.TargetServer), StringComparer.OrdinalIgnoreCase);
        static string Who(string? domain, string? user) => domain is null ? user! : $"{domain}\\{user}";

        return bySession.Select(g => g.Key).Concat(byHandoff.Select(g => g.Key)).Where(k => k.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(k =>
            {
                var ss = bySession[k].ToList();
                var hs = byHandoff[k].ToList();
                var address = ss.Select(s => s.TargetHost).FirstOrDefault(IpUtil.IsIp);
                var names = ss.Select(s => s.TargetHostName).Concat(ss.Select(s => s.TargetHost)).Concat(hs.Select(e => e.TargetServer))
                    .Where(n => n is not null && !IpUtil.IsIp(n)).Select(n => n!)
                    .GroupBy(n => n, StringComparer.OrdinalIgnoreCase).OrderByDescending(n => n.Count()).Select(n => n.Key).ToList();
                var remote = address ?? names.FirstOrDefault() ?? k;
                var times = ss.Select(s => s.Start).Concat(ss.Select(s => s.End)).Concat(hs.Select(e => e.Timestamp)).ToList();
                return new RemoteHostPivot
                {
                    RemoteHost = remote,
                    Name = JoinOrNull(names.Where(n => !string.Equals(n, remote, StringComparison.OrdinalIgnoreCase)).Take(3)),
                    IsCollected = names.Any(n => collected.Contains(HostKey.Of(n))) || collected.Contains(k),
                    FirstSeen = times.Min(),
                    LastSeen = times.Max(),
                    Connections = ss.Count,
                    Rdp = ss.Count(s => s.Technique == RemoteTechnique.Rdp),
                    RemoteExec = ss.Count(s => s.Technique != RemoteTechnique.Rdp),
                    ExplicitCreds = hs.Count,
                    Techniques = JoinOrNull(ss.GroupBy(s => s.Technique).OrderByDescending(t => t.Count()).Select(t => $"{t.Key} x{t.Count()}")),
                    FromHosts = JoinOrNull(ss.Select(s => HostKey.Of(s.Host)).Concat(hs.Select(e => HostKey.Of(e.Hostname)))
                        .Where(h => h.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)),
                    Users = JoinOrNull(ss.Where(s => s.User is not null).Select(s => Who(s.Domain, s.User))
                        .Concat(hs.Select(e => Who(e.SubjectDomain, e.SubjectUserName))).Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                    InferredUsers = JoinOrNull(ss.Where(s => s.User is null && s.InferredUser is not null).Select(s => s.InferredUser!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)),
                    CredentialsUsed = JoinOrNull(ss.Select(s => s.CredentialsUsed).Where(c => c is not null).Select(c => c!)
                        .Concat(hs.Where(e => e.TargetUserName is not null && !UserKey.Same(e.TargetUserName, e.SubjectUserName))
                            .Select(e => Who(e.TargetDomain, e.TargetUserName)))
                        .Distinct(StringComparer.OrdinalIgnoreCase).Take(8)),
                    IsIoc = iocs is not null && (iocs.MatchesIp(remote) || iocs.MatchesHost(remote) || names.Any(iocs.MatchesHost)),
                };
            })
            .OrderByDescending(p => p.Connections).ThenByDescending(p => p.ExplicitCreds).ThenBy(p => p.RemoteHost);
    }

    private static string? JoinOrNull(IEnumerable<string> values)
    {
        var l = values.ToList();
        return l.Count == 0 ? null : string.Join("; ", l);
    }

    /// <summary>
    /// Privileged logons, counted once per logon session: an elevated 4624 and its 4672 share a
    /// logon id. Events without a logon id count individually.
    /// </summary>
    private static int PrivilegedLogons(IEnumerable<NormalizedEvent> g)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var loose = 0;
        foreach (var e in g.Where(e => e.IsPrivileged))
        {
            if (e.LogonId is null) loose++;
            else seen.Add(HostKey.Of(e.Hostname) + "|" + e.LogonId);
        }
        return seen.Count + loose;
    }

    private static int Distinct(IEnumerable<NormalizedEvent> g, Func<NormalizedEvent, string?> key) =>
        g.Select(key).Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();

    private static string? Top(IEnumerable<NormalizedEvent> g, Func<NormalizedEvent, string?> key)
    {
        var top = g.Select(key).Where(v => !string.IsNullOrWhiteSpace(v))
            .GroupBy(v => v!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(x => x.Count()).Take(8).Select(x => x.Key).ToList();
        return top.Count == 0 ? null : string.Join("; ", top);
    }

    /// <summary>Heuristic 0-100 suspicion score, weighting fan-out, remote execution and privilege highest.</summary>
    private static int Score(int failed, int hosts, int rdp, int priv, int expl, int remoteExec, int remoteAccessTool = 0)
    {
        int score = 0;
        score += Math.Min(failed, 25);          // brute-force pressure
        if (hosts >= 3) score += 15;            // fan-out / lateral movement
        if (hosts >= 8) score += 10;
        score += Math.Min(rdp * 2, 10);
        score += Math.Min(priv * 3, 15);
        score += Math.Min(expl * 3, 10);
        score += Math.Min(remoteExec * 10, 30);
        score += Math.Min(remoteAccessTool * 10, 20);
        return Math.Min(score, 100);
    }
}
