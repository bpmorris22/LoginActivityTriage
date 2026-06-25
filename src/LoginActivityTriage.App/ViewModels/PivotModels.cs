using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.App.ViewModels;

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
    public int Explicit { get; init; }
    public int Privileged { get; init; }
    public int SuspicionScore { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>Aggregated activity grouped by user.</summary>
public sealed class UserPivot
{
    public string User { get; init; } = "";
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int Hosts { get; init; }
    public int SourceIps { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    public int Rdp { get; init; }
    public int Explicit { get; init; }
    public int Privileged { get; init; }
    public int SuspicionScore { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>Aggregated activity grouped by destination host.</summary>
public sealed class HostPivot
{
    public string Host { get; init; } = "";
    public DateTimeOffset FirstSeen { get; init; }
    public DateTimeOffset LastSeen { get; init; }
    public int Users { get; init; }
    public int SourceIps { get; init; }
    public int Successful { get; init; }
    public int Failed { get; init; }
    public int Rdp { get; init; }
    public int Privileged { get; init; }
    public bool IsIoc { get; init; }
}

/// <summary>Builds the pivot projections (and a simple suspicion score) from events.</summary>
public static class PivotBuilder
{
    public static IEnumerable<SourceIpPivot> BySourceIp(IEnumerable<NormalizedEvent> events, IocSet? iocs = null) =>
        events.Where(e => !string.IsNullOrWhiteSpace(e.SourceIp))
            .GroupBy(e => e.SourceIp!, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                int failed = g.Count(e => e.IsFailure);
                int hosts = Distinct(g, e => e.Hostname);
                int rdp = g.Count(e => e.IsRdp);
                int priv = g.Count(e => e.IsPrivileged);
                int expl = g.Count(e => e.EventId == 4648);
                return new SourceIpPivot
                {
                    SourceIp = g.Key,
                    FirstSeen = g.Min(e => e.Timestamp),
                    LastSeen = g.Max(e => e.Timestamp),
                    UniqueUsers = Distinct(g, e => e.TargetUserName),
                    UniqueHosts = hosts,
                    Successful = g.Count(e => e.IsSuccess),
                    Failed = failed,
                    Rdp = rdp,
                    Explicit = expl,
                    Privileged = priv,
                    SuspicionScore = Score(failed, hosts, rdp, priv, expl),
                    IsIoc = iocs?.MatchesIp(g.Key) ?? false,
                };
            })
            .OrderByDescending(p => p.SuspicionScore).ThenByDescending(p => p.Failed);

    public static IEnumerable<UserPivot> ByUser(IEnumerable<NormalizedEvent> events, IocSet? iocs = null) =>
        events.Where(e => !string.IsNullOrWhiteSpace(e.TargetUserName))
            .GroupBy(e => e.TargetUserName!, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                int failed = g.Count(e => e.IsFailure);
                int hosts = Distinct(g, e => e.Hostname);
                int rdp = g.Count(e => e.IsRdp);
                int priv = g.Count(e => e.IsPrivileged);
                int expl = g.Count(e => e.EventId == 4648);
                return new UserPivot
                {
                    User = g.Key,
                    FirstSeen = g.Min(e => e.Timestamp),
                    LastSeen = g.Max(e => e.Timestamp),
                    Hosts = hosts,
                    SourceIps = Distinct(g, e => e.SourceIp),
                    Successful = g.Count(e => e.IsSuccess),
                    Failed = failed,
                    Rdp = rdp,
                    Explicit = expl,
                    Privileged = priv,
                    SuspicionScore = Score(failed, hosts, rdp, priv, expl),
                    IsIoc = iocs?.MatchesUser(g.Key) ?? false,
                };
            })
            .OrderByDescending(p => p.SuspicionScore).ThenByDescending(p => p.Failed);

    public static IEnumerable<HostPivot> ByHost(IEnumerable<NormalizedEvent> events, IocSet? iocs = null) =>
        events.Where(e => !string.IsNullOrWhiteSpace(e.Hostname))
            .GroupBy(e => e.Hostname!, StringComparer.OrdinalIgnoreCase)
            .Select(g => new HostPivot
            {
                Host = g.Key,
                FirstSeen = g.Min(e => e.Timestamp),
                LastSeen = g.Max(e => e.Timestamp),
                Users = Distinct(g, e => e.TargetUserName),
                SourceIps = Distinct(g, e => e.SourceIp),
                Successful = g.Count(e => e.IsSuccess),
                Failed = g.Count(e => e.IsFailure),
                Rdp = g.Count(e => e.IsRdp),
                Privileged = g.Count(e => e.IsPrivileged),
                IsIoc = iocs?.MatchesHost(g.Key) ?? false,
            })
            .OrderByDescending(p => p.Successful + p.Failed);

    private static int Distinct(IEnumerable<NormalizedEvent> g, Func<NormalizedEvent, string?> key) =>
        g.Select(key).Where(v => !string.IsNullOrWhiteSpace(v))
            .Distinct(StringComparer.OrdinalIgnoreCase).Count();

    /// <summary>Heuristic 0-100 suspicion score, weighting fan-out and privilege highest.</summary>
    private static int Score(int failed, int hosts, int rdp, int priv, int expl)
    {
        int score = 0;
        score += Math.Min(failed, 25);          // brute-force pressure
        if (hosts >= 3) score += 20;            // fan-out / lateral movement
        if (hosts >= 8) score += 15;
        score += Math.Min(rdp * 2, 15);
        score += Math.Min(priv * 5, 20);
        score += Math.Min(expl * 3, 15);
        return Math.Min(score, 100);
    }
}
