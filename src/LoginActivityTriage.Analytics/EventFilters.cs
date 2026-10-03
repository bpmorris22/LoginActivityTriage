using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Analytics;

/// <summary>
/// Host boot moments (System 6005, Security 4608). Logon ids are unique only within one boot, so
/// every logon-id correlation stops at the next boot.
/// </summary>
public static class BootTimes
{
    public static bool IsBoot(NormalizedEvent e) => e.Activity == EventActivity.Boot || e.EventId is 6005 or 4608;

    /// <summary>Time-ordered boot times per host key.</summary>
    public static Dictionary<string, List<DateTimeOffset>> ByHost(IEnumerable<NormalizedEvent> events) =>
        events.Where(IsBoot).GroupBy(e => HostKey.Of(e.Hostname))
            .ToDictionary(g => g.Key, g => g.Select(e => e.Timestamp).OrderBy(t => t).ToList(), StringComparer.OrdinalIgnoreCase);

    /// <summary>True when a boot lies in (from, to].</summary>
    public static bool Between(List<DateTimeOffset>? boots, DateTimeOffset from, DateTimeOffset to)
    {
        if (boots is null || boots.Count == 0 || to <= from) return false;
        var i = LowerBound(boots, from);
        while (i < boots.Count && boots[i] <= from) i++;
        return i < boots.Count && boots[i] <= to;
    }

    /// <summary>First boot strictly after <paramref name="t"/>, or null.</summary>
    public static DateTimeOffset? After(List<DateTimeOffset>? boots, DateTimeOffset t)
    {
        if (boots is null) return null;
        var i = LowerBound(boots, t);
        while (i < boots.Count && boots[i] <= t) i++;
        return i < boots.Count ? boots[i] : null;
    }

    private static int LowerBound(List<DateTimeOffset> list, DateTimeOffset t)
    {
        int lo = 0, hi = list.Count;
        while (lo < hi) { var mid = (lo + hi) / 2; if (list[mid] < t) lo = mid + 1; else hi = mid; }
        return lo;
    }
}

/// <summary>
/// Resolves process-creation events (4688 / Sysmon 1) that were imported provisionally:
/// they are kept only when they ran inside a remote logon session (network, RDP) on the same
/// host. This keeps "what did the attacker run in that session" without importing every
/// process on the box. The session is the logon EFFECTIVE at the process's time: the latest 4624
/// with that id, unless a boot intervened (logon ids repeat after a reboot).
/// </summary>
public static class ProcessEventFilter
{
    public static List<NormalizedEvent> Apply(IEnumerable<NormalizedEvent> events) =>
        Apply(events, Array.Empty<NormalizedEvent>());

    /// <param name="events">Events to resolve (typically one import batch).</param>
    /// <param name="context">Additional events already in the case whose logons count as remote.</param>
    public static List<NormalizedEvent> Apply(IEnumerable<NormalizedEvent> events, IEnumerable<NormalizedEvent> context)
    {
        var list = events as IList<NormalizedEvent> ?? events.ToList();
        var all = list.Concat(context).ToList();
        var boots = BootTimes.ByHost(all);
        var logons = new Dictionary<string, List<NormalizedEvent>>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in all.Where(e => e.EventId == 4624).OrderBy(e => e.Timestamp))
        {
            var host = HostKey.Of(e.Hostname);
            foreach (var id in new[] { e.LogonId, e.LinkedLogonId })
            {
                if (id is null) continue;
                if (!logons.TryGetValue(host + "|" + id, out var l)) logons[host + "|" + id] = l = new List<NormalizedEvent>();
                l.Add(e);
            }
        }

        bool RemoteAt(string host, string? id, DateTimeOffset t)
        {
            if (id is null || !logons.TryGetValue(host + "|" + id, out var l)) return false;
            var effective = l.LastOrDefault(x => x.Timestamp <= t.AddSeconds(5)); // slack for event ordering
            if (effective is null || BootTimes.Between(boots.GetValueOrDefault(host), effective.Timestamp, t)) return false;
            return effective.LogonType is 3 or 10 or 12 && !effective.IsNoiseAccount;
        }

        var kept = new List<NormalizedEvent>(list.Count);
        foreach (var e in list)
        {
            if (!e.KeepOnlyIfLinked) { kept.Add(e); continue; }
            var host = HostKey.Of(e.Hostname);
            if (RemoteAt(host, e.LogonId, e.Timestamp) || RemoteAt(host, e.SubjectLogonId, e.Timestamp))
            {
                e.KeepOnlyIfLinked = false;
                kept.Add(e);
            }
        }
        return kept;
    }
}

/// <summary>Routine machine / system-account authentication that dominates volume on servers and DCs.</summary>
public static class NoiseFilter
{
    private static readonly HashSet<int> RoutineIds = new() { 4624, 4634, 4647, 4672, 4768, 4769, 4776 };

    /// <summary>
    /// True for successful logon / logoff / ticket events of machine, SYSTEM, service, DWM/UMFD or
    /// anonymous accounts, and scheduled-task UPDATES (4702) made by those accounts (Windows
    /// maintenance rewrites its own tasks constantly). Task creation (4698) is never dropped.
    /// Also drops system-account logon failures with STATUS_INVALID_SERVER_STATE (0xC00000DC):
    /// a service logon attempted while LSA / SAM was shutting down or starting - not a credential failure.
    /// </summary>
    public static bool IsRoutineNoise(NormalizedEvent e) =>
        e.Technique is null &&
        ((!e.IsFailure &&
          ((RoutineIds.Contains(e.EventId) && e.IsNoiseAccount) ||
           (e.EventId == 4702 && AccountClassifier.IsNoise(e.SubjectUserName, e.Sid)) ||
           // Explicit credentials used by the computer account / SYSTEM against THIS machine:
           // winlogon / wininit starting DWM and UMFD, svchost completing an interactive logon,
           // taskhostw for scheduled tasks. A system account using credentials against a REMOTE
           // server is kept.
           (e.EventId == 4648 && AccountClassifier.IsNoise(e.SubjectUserName) &&
            HostKey.IsLocal(e.TargetServer, e.Hostname)))) ||
         (e.EventId == 4625 && e.IsNoiseAccount && (IsInvalidServerState(e.Status) || IsInvalidServerState(e.SubStatus))));

    private static bool IsInvalidServerState(string? status) =>
        string.Equals(status?.Trim(), "0xC00000DC", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Fills in the account name for events that carry only a SID (7045 service installs, WinRM 91,
/// PowerShell events) from other events on the same host that pair that SID with a name.
/// </summary>
public static class SidResolver
{
    public static int Apply(IEnumerable<NormalizedEvent> events)
    {
        var list = events as IList<NormalizedEvent> ?? events.ToList();
        var names = new Dictionary<string, (string User, string? Domain)>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in list)
        {
            if (e.Sid is null || e.TargetUserName is null || AccountClassifier.IsWellKnownServiceSid(e.Sid)) continue;
            if (e.EventId is 4728 or 4732 or 4756) continue; // member SID with group-centric naming
            names.TryAdd(e.Sid, (e.TargetUserName, e.TargetDomain));
        }
        var resolved = 0;
        foreach (var e in list)
        {
            if (e.TargetUserName is not null || e.Sid is null || !names.TryGetValue(e.Sid, out var n)) continue;
            e.TargetUserName = n.User;
            e.TargetDomain ??= n.Domain;
            resolved++;
        }
        return resolved;
    }
}

/// <summary>Each host's UTC offset, from the most recent System 6013 event in its logs.</summary>
public static class HostTimeZones
{
    public static Dictionary<string, TimeZoneInfo> FromEvents(IEnumerable<NormalizedEvent> events) =>
        events.Where(e => e.EventId == 6013 && e.UtcOffsetMinutes is not null && e.Hostname is not null)
            .GroupBy(e => HostKey.Of(e.Hostname))
            .ToDictionary(
                g => g.Key,
                g => TimeZoneUtil.FixedOffset(g.OrderByDescending(e => e.Timestamp).First().UtcOffsetMinutes!.Value, "from host event 6013"),
                StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Chooses the events for the compact triage timeline (timeline.csv) that the HTA viewer loads.
/// Routine successful network authentication that is not part of a stitched session - the bulk
/// of a domain controller or file server log - stays in the full events.csv only, as do WinRM
/// client errors outside a session (local management agents poll WinRM and log 161/142 constantly).
/// </summary>
public static class TriageTimeline
{
    public static bool Include(NormalizedEvent e)
    {
        if (e.RemoteSessionRef is not null || e.Technique is not null || e.IsFailure || e.IsIoc) return true;
        return e.EventId switch
        {
            142 or 161 when IsWinRm(e) => false,
            4634 or 4647 => false,
            4624 => e.LogonType is not 3 || IpUtil.IsPublic(e.SourceIp),
            4672 => false,
            4768 or 4769 or 4776 => false,
            4648 => !AccountClassifier.IsNoise(e.SubjectUserName),
            6013 => false,
            _ => true,
        };
    }

    private static bool IsWinRm(NormalizedEvent e) =>
        (e.Provider?.Contains("WinRM", StringComparison.OrdinalIgnoreCase) ?? false) ||
        (e.Channel?.Contains("WinRM", StringComparison.OrdinalIgnoreCase) ?? false);
}
