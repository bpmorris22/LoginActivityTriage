using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Analytics;

/// <summary>
/// Rule-based detection over a set of normalised events. The MVP ships a focused
/// subset of the full rule catalogue; each rule is independent and additive so
/// the remaining rules can be dropped in without touching the runner.
/// </summary>
public sealed class SuspiciousSequenceAnalyzer
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(30);

    /// <summary>Business hours are 07:00-19:00 local-equivalent (UTC offsets preserved).</summary>
    private const int BusinessStartHour = 7;
    private const int BusinessEndHour = 19;

    public IReadOnlyList<Finding> Analyze(IEnumerable<NormalizedEvent> events)
    {
        var ordered = events.OrderBy(e => e.Timestamp).ToList();
        var findings = new List<Finding>();

        findings.AddRange(FailedThenSuccess(ordered));
        findings.AddRange(SourceIpToManyHosts(ordered));
        findings.AddRange(UserToManyHosts(ordered));
        findings.AddRange(AfterHours(ordered));
        findings.AddRange(ExplicitThenLogon(ordered));
        findings.AddRange(LogonThenPrivilege(ordered));

        return findings;
    }

    // Rule 2: explicit credential use (4648) followed by a logon (4624) for the same user.
    private static IEnumerable<Finding> ExplicitThenLogon(List<NormalizedEvent> events)
    {
        var logons = events.Where(e => e.EventId == 4624).ToList();
        foreach (var ex in events.Where(e => e.EventId == 4648 &&
                                             !string.IsNullOrWhiteSpace(e.TargetUserName)))
        {
            var match = logons.FirstOrDefault(l =>
                string.Equals(l.TargetUserName, ex.TargetUserName, StringComparison.OrdinalIgnoreCase) &&
                l.Timestamp >= ex.Timestamp && l.Timestamp - ex.Timestamp <= Window);
            if (match is not null)
            {
                yield return new Finding
                {
                    Severity = FindingSeverity.Medium,
                    RuleName = "Explicit credentials then logon",
                    Description = $"4648 explicit credential use for {ex.TargetUserName} followed by 4624 logon",
                    Timestamp = match.Timestamp,
                    User = ex.TargetUserName,
                    SourceIp = ex.SourceIp ?? match.SourceIp,
                    Host = match.Hostname ?? ex.Hostname,
                    RelatedEventIds = "4648,4624",
                    Reasoning = "Use of explicit alternate credentials immediately followed by a logon "
                              + "is common in run-as / pass-the-credential and admin pivoting.",
                };
            }
        }
    }

    // Rule 3: a logon (4624) followed by special privileges assigned (4672) for the same user and host.
    private static IEnumerable<Finding> LogonThenPrivilege(List<NormalizedEvent> events)
    {
        var privs = events.Where(e => e.EventId == 4672).ToList();
        foreach (var logon in events.Where(e => e.EventId == 4624 &&
                                                !e.IsMachineAccount &&
                                                !string.IsNullOrWhiteSpace(e.TargetUserName)))
        {
            var match = privs.FirstOrDefault(p =>
                string.Equals(p.TargetUserName, logon.TargetUserName, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(p.Hostname, logon.Hostname, StringComparison.OrdinalIgnoreCase) &&
                p.Timestamp >= logon.Timestamp && p.Timestamp - logon.Timestamp <= TimeSpan.FromMinutes(2));
            if (match is not null)
            {
                yield return new Finding
                {
                    Severity = FindingSeverity.Low,
                    RuleName = "Privileged logon session",
                    Description = $"{logon.TargetUserName} logged on to {logon.Hostname} and was assigned special privileges",
                    Timestamp = logon.Timestamp,
                    User = logon.TargetUserName,
                    SourceIp = logon.SourceIp,
                    Host = logon.Hostname,
                    RelatedEventIds = "4624,4672",
                    Reasoning = "A 4624 logon paired with a 4672 indicates a privileged/administrative "
                              + "session; review whether the elevation was expected for this account.",
                };
            }
        }
    }

    // Rule 1: failed logons followed by a successful logon from the same source IP.
    private static IEnumerable<Finding> FailedThenSuccess(List<NormalizedEvent> events)
    {
        foreach (var group in events
                     .Where(e => !string.IsNullOrWhiteSpace(e.SourceIp) && (e.IsFailure || e.IsSuccess))
                     .GroupBy(e => e.SourceIp))
        {
            var seq = group.OrderBy(e => e.Timestamp).ToList();
            for (var i = 0; i < seq.Count; i++)
            {
                if (!seq[i].IsSuccess) continue;
                var failsBefore = seq.Take(i)
                    .Count(e => e.IsFailure && seq[i].Timestamp - e.Timestamp <= Window);
                if (failsBefore >= 3)
                {
                    yield return new Finding
                    {
                        Severity = failsBefore >= 10 ? FindingSeverity.High : FindingSeverity.Medium,
                        RuleName = "Failed logons followed by success",
                        Description = $"{failsBefore} failed logon(s) then success from {group.Key}",
                        Timestamp = seq[i].Timestamp,
                        User = seq[i].TargetUserName,
                        SourceIp = group.Key,
                        Host = seq[i].Hostname,
                        RelatedEventIds = "4625,4624",
                        Reasoning = "Multiple authentication failures immediately preceding a success "
                                  + "from one source is a classic password-guessing / spray success pattern.",
                    };
                    break; // one finding per source IP is enough to flag
                }
            }
        }
    }

    // Rule 5: same source IP authenticating to multiple hosts within 30 minutes.
    private static IEnumerable<Finding> SourceIpToManyHosts(List<NormalizedEvent> events)
    {
        foreach (var group in events
                     .Where(e => !string.IsNullOrWhiteSpace(e.SourceIp) && !string.IsNullOrWhiteSpace(e.Hostname))
                     .GroupBy(e => e.SourceIp))
        {
            var hit = FindManyDistinctInWindow(group.ToList(), e => e.Hostname!, 3);
            if (hit is not null)
            {
                yield return new Finding
                {
                    Severity = FindingSeverity.Medium,
                    RuleName = "Source IP touching many hosts",
                    Description = $"{group.Key} authenticated to {hit.Value.Count} hosts within 30 minutes",
                    Timestamp = hit.Value.At,
                    SourceIp = group.Key,
                    Host = hit.Value.Sample,
                    RelatedEventIds = "4624,4625",
                    Reasoning = "One source reaching many hosts in a short window is consistent with "
                              + "lateral movement or scanning.",
                };
            }
        }
    }

    // Rule 6: same user logging into many hosts within 30 minutes.
    private static IEnumerable<Finding> UserToManyHosts(List<NormalizedEvent> events)
    {
        foreach (var group in events
                     .Where(e => e.IsSuccess && !e.IsMachineAccount &&
                                 !string.IsNullOrWhiteSpace(e.TargetUserName) &&
                                 !string.IsNullOrWhiteSpace(e.Hostname))
                     .GroupBy(e => e.TargetUserName))
        {
            var hit = FindManyDistinctInWindow(group.ToList(), e => e.Hostname!, 3);
            if (hit is not null)
            {
                yield return new Finding
                {
                    Severity = FindingSeverity.Medium,
                    RuleName = "User logging into many hosts",
                    Description = $"{group.Key} logged into {hit.Value.Count} hosts within 30 minutes",
                    Timestamp = hit.Value.At,
                    User = group.Key,
                    Host = hit.Value.Sample,
                    RelatedEventIds = "4624",
                    Reasoning = "A single account authenticating across many hosts quickly can indicate "
                              + "credential theft and lateral movement.",
                };
            }
        }
    }

    // Rule 10: successful logon outside business hours.
    private static IEnumerable<Finding> AfterHours(List<NormalizedEvent> events)
    {
        foreach (var e in events.Where(e => e.IsSuccess && !e.IsMachineAccount))
        {
            var hour = e.Timestamp.Hour;
            if (hour < BusinessStartHour || hour >= BusinessEndHour)
            {
                yield return new Finding
                {
                    Severity = FindingSeverity.Low,
                    RuleName = "After-hours logon",
                    Description = $"Logon by {e.TargetUserName} at {e.Timestamp:HH:mm}",
                    Timestamp = e.Timestamp,
                    User = e.TargetUserName,
                    SourceIp = e.SourceIp,
                    Host = e.Hostname,
                    RelatedEventIds = e.EventId.ToString(),
                    Reasoning = $"Logon occurred outside {BusinessStartHour:00}:00-{BusinessEndHour:00}:00, "
                              + "which warrants review against the user's normal pattern.",
                };
            }
        }
    }

    private readonly record struct WindowHit(int Count, DateTimeOffset At, string Sample);

    /// <summary>
    /// Sliding-window check: returns the first window where the number of distinct
    /// key values reaches <paramref name="threshold"/>.
    /// </summary>
    private static WindowHit? FindManyDistinctInWindow(
        List<NormalizedEvent> items, Func<NormalizedEvent, string> key, int threshold)
    {
        var seq = items.OrderBy(e => e.Timestamp).ToList();
        var start = 0;
        for (var end = 0; end < seq.Count; end++)
        {
            while (seq[end].Timestamp - seq[start].Timestamp > Window) start++;
            var distinct = seq.Skip(start).Take(end - start + 1)
                .Select(key).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (distinct.Count >= threshold)
                return new WindowHit(distinct.Count, seq[end].Timestamp, distinct[0]);
        }
        return null;
    }
}
