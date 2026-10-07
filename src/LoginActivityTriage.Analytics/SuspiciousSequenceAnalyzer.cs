using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Analytics;

/// <summary>Tuning for the analytics rules.</summary>
public sealed class AnalyzerOptions
{
    /// <summary>Time zone the business-hours rule is evaluated in (event times are UTC).</summary>
    public TimeZoneInfo TimeZone { get; init; } = TimeZoneInfo.Utc;

    /// <summary>
    /// When true, each host's own zone (from its System 6013 events) is used for the business-hours
    /// rule, falling back to <see cref="TimeZone"/> for hosts without one.
    /// </summary>
    public bool UseHostTimeZones { get; init; }
    public int BusinessStartHour { get; init; } = 7;
    public int BusinessEndHour { get; init; } = 19;
    public bool WeekendIsAfterHours { get; init; } = true;
    public TimeSpan Window { get; init; } = TimeSpan.FromMinutes(30);
}

/// <summary>Result of a full analysis pass.</summary>
public sealed class AnalysisResult
{
    public required List<RemoteSession> Sessions { get; init; }
    public required List<Finding> Findings { get; init; }
    /// <summary>Zone used per host for the business-hours rule.</summary>
    public Dictionary<string, TimeZoneInfo> HostZones { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Rule-based detection over normalised events and stitched remote sessions. Every rule is
/// independent and aggregates its hits so one behaviour yields one finding with a count.
/// </summary>
public sealed class SuspiciousSequenceAnalyzer
{
    private readonly AnalyzerOptions _o;
    private Dictionary<string, TimeZoneInfo> _hostZones = new(StringComparer.OrdinalIgnoreCase);

    public SuspiciousSequenceAnalyzer(AnalyzerOptions? options = null) => _o = options ?? new AnalyzerOptions();

    /// <summary>Builds remote sessions and runs every rule.</summary>
    public AnalysisResult Run(IEnumerable<NormalizedEvent> events)
    {
        var ordered = events.Where(e => e.Timestamp != DateTimeOffset.MinValue).OrderBy(e => e.Timestamp).ToList();
        SidResolver.Apply(ordered);
        _hostZones = _o.UseHostTimeZones ? HostTimeZones.FromEvents(ordered) : new(StringComparer.OrdinalIgnoreCase);
        var sessions = new RemoteSessionBuilder().Build(ordered);
        InferOutboundUsers(ordered, sessions);
        var findings = Analyze(ordered, sessions);
        return new AnalysisResult { Sessions = sessions, Findings = findings, HostZones = _hostZones };
    }

    /// <summary>
    /// Outbound sessions whose logs name no account (no credential hand-off recorded) get an
    /// <see cref="RemoteSession.InferredUser"/> when exactly one real account logged on
    /// interactively (console, unlock, cached, RDP) to that host anywhere in the evidence. This is
    /// an inference - the account's own logon may predate the logs - so User stays empty and the
    /// basis is written to the session's Evidence.
    /// </summary>
    internal static void InferOutboundUsers(IEnumerable<NormalizedEvent> events, IEnumerable<RemoteSession> sessions)
    {
        var interactive = events
            .Where(e => e.EventId == 4624 && e.LogonType is 2 or 7 or 10 or 11 or 12 && e.TargetUserName is not null && !e.IsNoiseAccount)
            .GroupBy(e => HostKey.Of(e.Hostname))
            .ToDictionary(g => g.Key,
                g => g.GroupBy(e => UserKey.Bare(e.TargetUserName), StringComparer.OrdinalIgnoreCase).Select(u => u.First()).ToList(),
                StringComparer.OrdinalIgnoreCase);
        foreach (var s in sessions.Where(s => s.Direction == "Outbound" && s.User is null))
        {
            if (!interactive.TryGetValue(HostKey.Of(s.Host), out var users) || users.Count != 1) continue;
            var u = users[0];
            s.InferredUser = UserKey.Bare(u.TargetUserName);
            var who = u.TargetDomain is null ? s.InferredUser : $"{u.TargetDomain}\\{s.InferredUser}";
            var basis = $"user INFERRED as {who}: no account recorded for this connection, and {who} is the only account " +
                        $"with an interactive logon on {HostKey.Of(s.Host)} in the collected logs";
            s.Evidence = s.Evidence is null ? basis : $"{s.Evidence}; {basis}";
        }
    }

    private TimeZoneInfo ZoneFor(string? host) =>
        _hostZones.TryGetValue(HostKey.Of(host), out var z) ? z : _o.TimeZone;

    /// <summary>Runs every rule (building sessions internally).</summary>
    public IReadOnlyList<Finding> Analyze(IEnumerable<NormalizedEvent> events) => Run(events).Findings;

    public List<Finding> Analyze(List<NormalizedEvent> ordered, IReadOnlyList<RemoteSession> sessions)
    {
        var findings = new List<Finding>();
        findings.AddRange(SessionFindings(sessions));
        findings.AddRange(OutboundFindings(sessions));
        findings.AddRange(UnlinkedSuspiciousServices(ordered));
        findings.AddRange(RemoteAccessTools(ordered, sessions));
        findings.AddRange(LogCleared(ordered));
        findings.AddRange(FailedThenSuccess(ordered));
        findings.AddRange(ConsoleFailedThenSuccess(ordered));
        findings.AddRange(PasswordSpray(ordered));
        findings.AddRange(FailureBurst(ordered));
        findings.AddRange(RdpPreAuthFlood(ordered));
        findings.AddRange(SourceIpToManyHosts(ordered));
        findings.AddRange(UserToManyHosts(ordered));
        findings.AddRange(ExternalRdp(ordered, sessions));
        findings.AddRange(ExternalNetworkLogon(ordered));
        findings.AddRange(ExternalRdpConnection(ordered));
        findings.AddRange(NewCredentialsLogon(ordered));
        findings.AddRange(LocalAccountNetworkLogon(ordered));
        findings.AddRange(ExplicitCredentials(ordered));
        findings.AddRange(PrivilegedGroupChanges(ordered));
        findings.AddRange(Kerberoasting(ordered));
        findings.AddRange(KerberosFanOut(ordered));
        findings.AddRange(Lockouts(ordered));
        findings.AddRange(AfterHours(ordered));
        findings.AddRange(PrivilegedRemoteLogons(ordered));
        return findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Timestamp).ToList();
    }

    // ================================================================= sessions

    private static IEnumerable<Finding> SessionFindings(IReadOnlyList<RemoteSession> sessions)
    {
        foreach (var s in sessions)
        {
            (FindingSeverity sev, string rule, string mitre, string why)? spec = (s.Technique, s.Direction) switch
            {
                (RemoteTechnique.PsExec, "Inbound") => (FindingSeverity.High, "PsExec-style remote service execution",
                    "T1569.002, T1021.002",
                    "A service binary / pipe pattern of PsExec or a clone (PAExec, RemCom, Impacket psexec/smbexec) ran on this host. Confirm the operator, source and commands."),
                (RemoteTechnique.ServiceInstall, "Inbound") => (FindingSeverity.High, "Service created remotely",
                    "T1543.003, T1569.002",
                    "A service was installed from a network logon or right after remote SCM / admin-share access - a common lateral-movement execution method."),
                (RemoteTechnique.PsRemoting, "Inbound") => (FindingSeverity.Medium, "PowerShell Remoting session",
                    "T1021.006",
                    "A WinRM / PowerShell remote session was opened on this host. Legitimate for admins; verify the user, source and commands."),
                (RemoteTechnique.WinRs, "Inbound") => (FindingSeverity.Medium, "WinRS remote shell",
                    "T1021.006", "A WinRM cmd shell (winrs) ran on this host."),
                (RemoteTechnique.Wmi, "Inbound") => (FindingSeverity.High, "Remote WMI execution",
                    "T1047", "A shell spawned by WmiPrvSE (or an Impacket wmiexec output file) indicates remote command execution via WMI."),
                (RemoteTechnique.Dcom, "Inbound") => (FindingSeverity.High, "Remote DCOM execution",
                    "T1021.003", "A shell spawned via a DCOM object (MMC20.Application / ShellWindows) indicates remote execution."),
                (RemoteTechnique.ScheduledTask, "Inbound") => (FindingSeverity.High, "Scheduled task created remotely",
                    "T1053.005", "A scheduled task was registered from a network logon (or matches Impacket atexec)."),
                (RemoteTechnique.AdminShare, "Inbound") => (FindingSeverity.High, "Write access to executable on admin share",
                    "T1021.002, T1570", "A share access check granted write access (WriteData / AppendData) to an executable or script on ADMIN$ / C$ - " +
                    "typical of lateral tool transfer. 5145 records the access, not a completed copy: confirm the file on the target (MFT / USN / Amcache)."),
                _ => null, // outbound sessions are aggregated per host and technique in OutboundFindings
            };
            if (spec is null) continue;
            var (sev, rule, mitre, why) = spec.Value;
            if (s.Confidence == "Low" && sev > FindingSeverity.Low) sev--;

            yield return new Finding
            {
                Severity = sev,
                RuleName = rule,
                Description = Describe(s),
                Timestamp = s.Start,
                User = s.User,
                SourceIp = s.SourceIp,
                Host = s.Host,
                RelatedEventIds = s.EventIds,
                Reasoning = $"{why} Evidence: {s.Evidence}. Confidence {s.Confidence}.",
                Mitre = mitre,
                Count = 1,
                SessionRef = s.Id,
            };
        }
    }

    /// <summary>One finding per (source host, technique) listing the targets, instead of one per connection.</summary>
    private static IEnumerable<Finding> OutboundFindings(IReadOnlyList<RemoteSession> sessions)
    {
        foreach (var g in sessions.Where(s => s.Direction == "Outbound" && s.Variant != "Hyper-V VM console (VMConnect)")
                     .GroupBy(s => (HostKey.Of(s.Host), s.Technique)))
        {
            (FindingSeverity sev, string rule, string mitre, string why) = g.Key.Technique switch
            {
                RemoteTechnique.PsExec => (FindingSeverity.Medium, "Outbound PsExec from this host", "T1569.002",
                    "This host launched PsExec / PAExec against other systems - expected only from admin workstations."),
                RemoteTechnique.Wmi => (FindingSeverity.Medium, "Outbound remote WMI from this host", "T1047",
                    "This host issued remote WMI commands."),
                RemoteTechnique.ScheduledTask or RemoteTechnique.RemoteServiceControl =>
                    (FindingSeverity.Medium, "Outbound remote task / service control", "T1053.005, T1543.003",
                     "This host created tasks or services on other systems."),
                RemoteTechnique.PsRemoting or RemoteTechnique.WinRs =>
                    (FindingSeverity.Low, "Outbound PowerShell Remoting from this host", "T1021.006",
                     "This host opened (or tried to open) WinRM sessions to other systems."),
                RemoteTechnique.Rdp => (FindingSeverity.Low, "Outbound RDP from this host", "T1021.001",
                    "This host connected to other systems over RDP."),
                RemoteTechnique.Smb => (FindingSeverity.Low, "Outbound SMB with explicit credentials from this host", "T1021.002, T1570",
                    "This host used explicit credentials for file or admin shares on other systems (4648 with a cifs/ SPN) - how tools are staged and data collected across hosts."),
                _ => (FindingSeverity.Low, $"Outbound {g.Key.Technique} from this host", "T1021", "This host accessed other systems."),
            };
            // One entry per destination: attempts to an address count together whether or not a
            // credential hand-off named the server for that particular attempt.
            var byTarget = g.GroupBy(s => HostKey.Of(s.TargetHost ?? s.TargetHostName), StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(t => t.Count()).ToList();
            var targets = byTarget.Take(10).Select(t =>
            {
                var addr = t.Select(s => s.TargetHost ?? s.TargetHostName).FirstOrDefault(x => x is not null) ?? "(unknown target)";
                var name = t.Select(s => s.TargetHostName).FirstOrDefault(x => x is not null && !string.Equals(x, addr, StringComparison.OrdinalIgnoreCase));
                return $"{addr}{(name is null ? "" : $" ({name})")} x{t.Count()}";
            }).ToList();
            if (byTarget.Count > 10) targets.Add($"{byTarget.Count - 10} more target(s)");
            var first = g.OrderBy(s => s.Start).First();
            var actors = g.Where(s => s.User is not null)
                .GroupBy(s => (s.Domain is null ? s.User : $"{s.Domain}\\{s.User}") + (s.CredentialsUsed is null ? "" : $" using {s.CredentialsUsed}"),
                    StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(a => a.Count()).Take(4).Select(a => $"{a.Key} ({a.Count()})").ToList();
            var inferred = g.Where(s => s.User is null && s.InferredUser is not null)
                .GroupBy(s => s.InferredUser!, StringComparer.OrdinalIgnoreCase).ToList();
            var unattributed = g.Count(s => s.User is null && s.InferredUser is null);
            yield return new Finding
            {
                Severity = sev,
                RuleName = rule,
                Description = $"{first.Host}: {g.Count()} outbound {g.Key.Technique} connection attempt(s) to {string.Join(", ", targets)}" +
                              (actors.Count == 0 ? "" : $"; by {string.Join("; ", actors)}") +
                              string.Concat(inferred.Select(i =>
                                  $"; {i.Count()} with no account in the logs - likely {i.Key}, the only interactive account on this host (inferred)")) +
                              (unattributed == 0 ? "" : $"; {unattributed} with no account in the logs"),
                Timestamp = first.Start,
                User = g.Select(s => s.User ?? s.CredentialsUsed).FirstOrDefault(u => u is not null),
                Host = first.Host,
                RelatedEventIds = string.Join(",", g.SelectMany(s => (s.EventIds ?? "").Split(',')).Where(x => x.Length > 0).Distinct()),
                Reasoning = $"{why} First {CsvTs(first.Start)}, last {CsvTs(g.Max(s => s.End))}.",
                Mitre = mitre,
                Count = g.Count(),
                SessionRef = first.Id,
            };
        }
    }

    private static string CsvTs(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static string Describe(RemoteSession s)
    {
        var who = s.User is null ? "unknown user" : (s.Domain is null ? s.User : $"{s.Domain}\\{s.User}");
        var from = s.SourceIp ?? s.SourceHost;
        var core = s.Direction == "Outbound"
            ? $"{s.Technique} from {s.Host} to {s.TargetHost ?? "unknown target"}{(s.TargetHostName is null ? "" : $" ({s.TargetHostName})")} by {who}" +
              (s.CredentialsUsed is null ? "" : $" using {s.CredentialsUsed}")
            : $"{s.Technique}{(s.Variant is null ? "" : $" ({s.Variant})")} on {s.Host} as {who}{(from is null ? "" : $" from {from}")}";
        return s.Detail is null ? core : $"{core} - {s.Detail}";
    }

    private static IEnumerable<Finding> UnlinkedSuspiciousServices(List<NormalizedEvent> events) =>
        events.Where(e => e.EventId is 7045 or 4697 && e.RemoteSessionRef is null &&
                          e.TechniqueDetail == "Service with command-line ImagePath")
            .GroupBy(e => (HostKey.Of(e.Hostname), e.ServiceName))
            .Select(g => new Finding
            {
                Severity = FindingSeverity.High,
                RuleName = "Service with command-line ImagePath",
                Description = $"Service '{g.First().ServiceName}' on {g.First().Hostname} runs: {g.First().ServiceFileName}",
                Timestamp = g.First().Timestamp,
                Host = g.First().Hostname,
                User = g.First().SubjectUserName,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct()),
                Reasoning = "Services whose ImagePath is a shell / PowerShell / script host are a hallmark of remote execution frameworks and persistence.",
                Mitre = "T1543.003",
                Count = g.Count(),
            });

    /// <summary>
    /// Third-party remote access / RMM software installed or started on a host. One finding per
    /// (host, tool). High when it runs from a temp / user-writable folder (portable or on-demand
    /// session) or appeared during a remote session on that host; otherwise Medium.
    /// </summary>
    private static IEnumerable<Finding> RemoteAccessTools(List<NormalizedEvent> events, IReadOnlyList<RemoteSession> sessions)
    {
        foreach (var g in events.Where(e => e.Technique == RemoteTechnique.RemoteAccessTool)
                     .GroupBy(e => (HostKey.Of(e.Hostname), e.TechniqueDetail ?? "remote access tool")))
        {
            var first = g.OrderBy(e => e.Timestamp).First();
            var path = g.Select(e => e.ServiceFileName ?? e.ProcessName).FirstOrDefault(p => p is not null);
            var install = g.FirstOrDefault(e => e.EventId is 7045 or 4697);
            var duringSession = sessions.FirstOrDefault(s =>
                s.Direction == "Inbound" && HostKey.Same(s.Host, first.Hostname) && first.Timestamp >= s.Start.AddMinutes(-5) && first.Timestamp <= s.End.AddMinutes(5));
            var portable = RemoteExecPatterns.IsUserWritablePath(path);
            var who = first.TargetUserName is null ? first.Sid : $"{first.TargetDomain}\\{first.TargetUserName}";
            yield return new Finding
            {
                Severity = portable || duringSession is not null ? FindingSeverity.High : FindingSeverity.Medium,
                RuleName = install is not null ? "Remote access software installed" : "Remote access software executed",
                Description = $"{g.Key.Item2} on {first.Hostname}" +
                              (install is not null ? $": service '{install.ServiceName}' installed" : ": started") +
                              (who is null ? "" : $" by {who}") +
                              (path is null ? "" : $" - {path}") +
                              (duringSession is null ? "" : $" (during {duringSession.Technique} session #{duringSession.Id})") +
                              (g.Count() > 1
                                  ? $"; {g.Count()} events, first {CsvTs(first.Timestamp)}, most recent {CsvTs(g.Max(e => e.Timestamp))}" +
                                    (g.OrderBy(e => e.Timestamp).Last() is var last && last.TargetUserName is not null && !UserKey.Same(last.TargetUserName, first.TargetUserName)
                                        ? $" by {last.TargetDomain}\\{last.TargetUserName}" : "")
                                  : ""),
                Timestamp = first.Timestamp,
                User = first.TargetUserName,
                Host = first.Hostname,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct()),
                Reasoning = "Third-party remote access tools give interactive control that bypasses RDP / WinRM logging and are a common " +
                            "persistence and hands-on-keyboard channel. Confirm it was sanctioned, who installed it and which sessions it served" +
                            (portable ? "; this binary runs from a temp / user-writable folder (portable or on-demand install)." : "."),
                Mitre = "T1219",
                Count = g.Count(),
                SessionRef = duringSession?.Id,
            };
        }
    }

    private static IEnumerable<Finding> LogCleared(List<NormalizedEvent> events) =>
        events.Where(e => e.Technique == RemoteTechnique.LogCleared).Select(e => new Finding
        {
            Severity = FindingSeverity.Critical,
            RuleName = "Event log cleared",
            Description = $"{e.Details} on {e.Hostname} by {e.TargetDomain}\\{e.TargetUserName}",
            Timestamp = e.Timestamp,
            User = e.TargetUserName,
            Host = e.Hostname,
            RelatedEventIds = e.EventId.ToString(),
            Reasoning = "Clearing event logs destroys evidence and is rarely legitimate during an incident window.",
            Mitre = "T1070.001",
        });

    // ================================================================= authentication

    // Failed logons followed by a success, per (source IP, account). Accounts are domain-aware:
    // DOMAIN-A\administrator failing and DOMAIN-B\administrator succeeding is not a guessing success.
    private IEnumerable<Finding> FailedThenSuccess(List<NormalizedEvent> events)
    {
        foreach (var group in events
                     .Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp) && e.TargetUserName is not null &&
                                 (e.IsFailure || (e.IsSuccess && e.EventId is 4624 or 4768 or 4776)))
                     .GroupBy(e => (e.SourceIp!, UserKey.Bare(e.TargetUserName).ToLowerInvariant())))
        {
            var seq = group.ToList();
            for (var i = 0; i < seq.Count; i++)
            {
                var ok = seq[i];
                if (!ok.IsSuccess) continue;
                var fails = 0; // look back only across the window (seq is time-ordered)
                for (var j = i - 1; j >= 0 && ok.Timestamp - seq[j].Timestamp <= _o.Window; j--)
                    if (seq[j].IsFailure && AccountKey.SameAccount(seq[j].TargetUserName, seq[j].TargetDomain, ok.TargetUserName, ok.TargetDomain))
                        fails++;
                if (fails < 3) continue;
                yield return new Finding
                {
                    Severity = fails >= 10 ? FindingSeverity.High : FindingSeverity.Medium,
                    RuleName = "Failed logons followed by success",
                    Description = $"{fails} failed logon(s) then success for {AccountKey.Of(ok.TargetUserName, ok.TargetDomain)} from {group.Key.Item1} on {seq[i].Hostname}",
                    Timestamp = seq[i].Timestamp,
                    User = seq[i].TargetUserName,
                    SourceIp = group.Key.Item1,
                    Host = seq[i].Hostname,
                    RelatedEventIds = string.Join(",", seq.Take(i + 1).Select(e => e.EventId).Distinct()),
                    Reasoning = "Repeated authentication failures immediately before a success for the same account and source is a password-guessing success pattern.",
                    Mitre = "T1110",
                    Count = fails,
                };
                break;
            }
        }
    }

    /// <summary>
    /// Failed logons at the keyboard followed by a success, per (host, user). The network rule above
    /// needs a source address; console (2), unlock (7) and cached-credential (11) logons carry none
    /// or 127.0.0.1. Remote-control software (Splashtop, AnyDesk, TeamViewer...) logs the same way,
    /// so the finding says when such a tool was already on the host.
    /// </summary>
    private IEnumerable<Finding> ConsoleFailedThenSuccess(List<NormalizedEvent> events)
    {
        var tools = events.Where(e => e.Technique == RemoteTechnique.RemoteAccessTool)
            .ToLookup(e => HostKey.Of(e.Hostname), StringComparer.OrdinalIgnoreCase);
        foreach (var group in events
                     .Where(e => e.EventId is 4624 or 4625 && e.LogonType is 2 or 7 or 11 && IpUtil.IsLocalOrBlank(e.SourceIp) &&
                                 e.TargetUserName is not null && !e.IsNoiseAccount && (e.IsFailure || e.CountsAsLogonSuccess))
                     .GroupBy(e => (HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant())))
        {
            var seq = group.ToList();
            var since = DateTimeOffset.MinValue; // failures already answered by an earlier success are not counted again
            for (var i = 0; i < seq.Count; i++)
            {
                var ok = seq[i];
                if (ok.EventId != 4624) continue;
                var fails = seq.Take(i).Where(e => e.IsFailure && e.Timestamp > since && ok.Timestamp - e.Timestamp <= _o.Window &&
                                                   AccountKey.SameAccount(e.TargetUserName, e.TargetDomain, ok.TargetUserName, ok.TargetDomain)).ToList();
                since = ok.Timestamp;
                if (fails.Count < 3) continue;

                var zone = ZoneFor(ok.Hostname);
                string Local(DateTimeOffset t) => TimeZoneInfo.ConvertTime(t, zone).ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
                var who = ok.TargetDomain is null ? ok.TargetUserName : $"{ok.TargetDomain}\\{ok.TargetUserName}";
                var reasons = string.Join(", ", fails.Select(f => f.FailureReason).Where(r => r is not null).Distinct(StringComparer.OrdinalIgnoreCase));
                var how = ok.LogonType switch
                {
                    11 => "with cached domain credentials (type 11), so no domain controller was reachable",
                    7 => "unlock (type 7)",
                    _ => "interactive (type 2)",
                };
                var rat = string.Join(", ", tools[group.Key.Item1].Where(t => t.Timestamp <= ok.Timestamp)
                    .Select(t => t.TechniqueDetail ?? "remote access tool").Distinct(StringComparer.OrdinalIgnoreCase));
                yield return new Finding
                {
                    Severity = fails.Count >= 10 ? FindingSeverity.Medium : FindingSeverity.Low,
                    RuleName = "Failed console logons followed by success",
                    Description = $"{fails.Count} failed console logon(s) for {who} on {ok.Hostname}" + (reasons.Length == 0 ? "" : $" ({reasons})") +
                                  $" {Local(fails[0].Timestamp)}-{Local(fails[^1].Timestamp)} {zone.Id} on {LocalDay(TimeZoneInfo.ConvertTime(ok.Timestamp, zone))}, " +
                                  $"then success at {Local(ok.Timestamp)} {how}" +
                                  (rat.Length == 0 ? "" : $"; remote access software already on this host ({rat}) also produces console logons"),
                    Timestamp = ok.Timestamp,
                    User = ok.TargetUserName,
                    Host = ok.Hostname,
                    RelatedEventIds = "4625,4624",
                    Reasoning = "Repeated bad passwords at the keyboard just before a success for the same account. Usually mistyping; it is also " +
                                "what local password guessing or a session through remote-control software looks like. Confirm the user was at the device.",
                    Mitre = "T1110",
                    Count = fails.Count,
                };
            }
        }
    }

    private IEnumerable<Finding> PasswordSpray(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.IsFailure && !IpUtil.IsLocalOrBlank(e.SourceIp) && e.TargetUserName is not null)
                     .GroupBy(e => e.SourceIp!))
        {
            var hit = DistinctInWindow(g.ToList(), e => AccountKey.Of(e.TargetUserName, e.TargetDomain), 8, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.High,
                RuleName = "Password spray",
                Description = $"{g.Key} failed authentication for {hit.Value.Count} different accounts within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                SourceIp = g.Key,
                Host = hit.Value.Event.Hostname,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct()),
                Reasoning = "Many accounts failing from one source in a short window is the signature of password spraying.",
                Mitre = "T1110.003",
                Count = hit.Value.Count,
            };
        }
    }

    private IEnumerable<Finding> FailureBurst(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.IsFailure && e.EventId != 4740 && !IpUtil.IsLocalOrBlank(e.SourceIp))
                     .GroupBy(e => e.SourceIp!))
        {
            var hit = CountInWindow(g.ToList(), 20, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "Authentication failure burst",
                Description = $"{hit.Value.Count} authentication failures from {g.Key} within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                SourceIp = g.Key,
                Host = hit.Value.Event.Hostname,
                User = hit.Value.Event.TargetUserName,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct()),
                Reasoning = "A high failure rate from one source indicates brute force or a misconfigured service holding stale credentials.",
                Mitre = "T1110.001",
                Count = hit.Value.Count,
            };
        }
    }

    private IEnumerable<Finding> RdpPreAuthFlood(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.EventId == 131 && e.Technique == RemoteTechnique.Rdp && !IpUtil.IsLocalOrBlank(e.SourceIp))
                     .GroupBy(e => (e.SourceIp!, HostKey.Of(e.Hostname))))
        {
            var hit = CountInWindow(g.ToList(), 30, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = IpUtil.IsPublic(g.Key.Item1) ? FindingSeverity.High : FindingSeverity.Medium,
                RuleName = "RDP connection flood (pre-auth)",
                Description = $"{hit.Value.Count} RDP TCP connections from {g.Key.Item1} to {hit.Value.Event.Hostname} within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                SourceIp = g.Key.Item1,
                Host = hit.Value.Event.Hostname,
                RelatedEventIds = "131",
                Reasoning = "Many pre-authentication RDP connections from one address indicate RDP brute force or scanning, even when no failed-logon events were recorded.",
                Mitre = "T1110, T1133",
                Count = hit.Value.Count,
            };
        }
    }

    private IEnumerable<Finding> SourceIpToManyHosts(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.EventId == 4624 && !e.IsNoiseAccount && e.LogonType is 3 or 10 &&
                                            !IpUtil.IsLocalOrBlank(e.SourceIp) && e.Hostname is not null)
                     .GroupBy(e => e.SourceIp!))
        {
            var hit = DistinctInWindow(g.ToList(), e => HostKey.Of(e.Hostname), 3, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "Source IP logging on to many hosts",
                Description = $"{g.Key} logged on to {hit.Value.Count} hosts within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                SourceIp = g.Key,
                Host = hit.Value.Event.Hostname,
                User = hit.Value.Event.TargetUserName,
                RelatedEventIds = "4624",
                Reasoning = "One source reaching many hosts in a short window is consistent with lateral movement (or an admin / management server - check the source).",
                Mitre = "T1021",
                Count = hit.Value.Count,
            };
        }
    }

    private IEnumerable<Finding> UserToManyHosts(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.EventId == 4624 && !e.IsNoiseAccount && e.LogonType is 3 or 10 &&
                                            e.TargetUserName is not null && e.Hostname is not null)
                     .GroupBy(e => UserKey.Bare(e.TargetUserName).ToLowerInvariant()))
        {
            var hit = DistinctInWindow(g.ToList(), e => HostKey.Of(e.Hostname), 3, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "User logging on to many hosts",
                Description = $"{hit.Value.Event.TargetUserName} logged on to {hit.Value.Count} hosts within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                User = hit.Value.Event.TargetUserName,
                Host = hit.Value.Event.Hostname,
                SourceIp = hit.Value.Event.SourceIp,
                RelatedEventIds = "4624",
                Reasoning = "A single account authenticating across many hosts quickly can indicate credential theft and lateral movement.",
                Mitre = "T1078, T1021",
                Count = hit.Value.Count,
            };
        }
    }

    private static IEnumerable<Finding> ExternalRdp(List<NormalizedEvent> events, IReadOnlyList<RemoteSession> sessions)
    {
        var hits = events.Where(e => ((e.EventId == 4624 && e.LogonType is 10 or 12) || (e.EventId == 21 && e.Technique == RemoteTechnique.Rdp)) &&
                                     IpUtil.IsPublic(e.SourceIp))
            .GroupBy(e => (e.SourceIp!, HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant()));
        foreach (var g in hits)
        {
            var first = g.First();
            yield return new Finding
            {
                Severity = FindingSeverity.High,
                RuleName = "RDP logon from external address",
                Description = $"{first.TargetUserName} logged on to {first.Hostname} over RDP from public address {g.Key.Item1}",
                Timestamp = first.Timestamp,
                User = first.TargetUserName,
                SourceIp = g.Key.Item1,
                Host = first.Hostname,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct()),
                Reasoning = "Successful RDP from a non-RFC1918 address means RDP is reachable from outside (or via a VPN that does not NAT) - a top initial-access vector.",
                Mitre = "T1133, T1021.001",
                Count = g.Count(),
                SessionRef = first.RemoteSessionRef,
            };
        }
    }

    /// <summary>
    /// A successful network logon (type 3, or 8 with a clear-text password) from a routable address:
    /// SMB, WinRM, RPC or another service on this host is reachable from the internet and the
    /// credentials worked. One finding per (address, host, account).
    /// </summary>
    private static IEnumerable<Finding> ExternalNetworkLogon(List<NormalizedEvent> events) =>
        events.Where(e => e.EventId == 4624 && e.LogonType is 3 or 8 && !e.IsNoiseAccount && IpUtil.IsPublic(e.SourceIp))
            .GroupBy(e => (e.SourceIp!, HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant()))
            .Select(g =>
            {
                var first = g.First();
                return new Finding
                {
                    Severity = FindingSeverity.High,
                    RuleName = "Network logon from external address",
                    Description = $"{first.TargetUserName} logged on to {first.Hostname} over the network (type {first.LogonType}, {first.AuthenticationPackage ?? "unknown package"}) " +
                                  $"from public address {g.Key.Item1}" + (g.Count() > 1 ? $", {g.Count()} times" : ""),
                    Timestamp = first.Timestamp,
                    User = first.TargetUserName,
                    SourceIp = g.Key.Item1,
                    Host = first.Hostname,
                    RelatedEventIds = "4624",
                    Reasoning = "A successful network logon from a non-RFC1918 address means SMB, WinRM, RPC or another service on this host is reachable " +
                                "from the internet (or through a VPN that does not NAT), and the credentials worked. Check what the session did next.",
                    Mitre = "T1133, T1021",
                    Count = g.Count(),
                    SessionRef = g.Select(e => e.RemoteSessionRef).FirstOrDefault(r => r is not null),
                };
            });

    /// <summary>
    /// RDP reached from a routable address with no session logon to show for it (Security log missing,
    /// or the connection never got past authentication): NLA authentication (RCM 1149) is High per
    /// address and account; bare connections (RdpCoreTS 131 / 140) are one Medium finding per host,
    /// so an exposed server scanned by many addresses does not drown the list.
    /// </summary>
    private static IEnumerable<Finding> ExternalRdpConnection(List<NormalizedEvent> events)
    {
        var loggedOn = events
            .Where(e => ((e.EventId == 4624 && e.LogonType is 10 or 12) || (e.EventId == 21 && e.Technique == RemoteTechnique.Rdp)) && IpUtil.IsPublic(e.SourceIp))
            .Select(e => (e.SourceIp!, HostKey.Of(e.Hostname))).ToHashSet();   // ExternalRdp already reports these
        var hits = events.Where(e => e.Technique == RemoteTechnique.Rdp && e.EventId is 1149 or 131 or 140 && IpUtil.IsPublic(e.SourceIp) &&
                                     !loggedOn.Contains((e.SourceIp!, HostKey.Of(e.Hostname)))).ToList();

        foreach (var g in hits.Where(e => e.EventId == 1149).GroupBy(e => (e.SourceIp!, HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant())))
        {
            var first = g.First();
            yield return new Finding
            {
                Severity = FindingSeverity.High,
                RuleName = "RDP authentication from external address",
                Description = $"{first.TargetUserName} passed RDP network-level authentication on {first.Hostname} from public address {g.Key.Item1}" +
                              (g.Count() > 1 ? $" {g.Count()} times" : "") + "; no session logon is recorded in the collected logs",
                Timestamp = first.Timestamp,
                User = first.TargetUserName,
                SourceIp = g.Key.Item1,
                Host = first.Hostname,
                RelatedEventIds = "1149",
                Reasoning = "RDP is reachable from the internet and these credentials passed NLA. Without the Security log (or with the session never " +
                            "completing) the 1149 is the only trace of the access attempt; treat it as a probable logon until the Security log says otherwise.",
                Mitre = "T1133, T1021.001",
                Count = g.Count(),
                SessionRef = first.RemoteSessionRef,
            };
        }

        foreach (var g in hits.Where(e => e.EventId is 131 or 140).GroupBy(e => HostKey.Of(e.Hostname)))
        {
            var first = g.OrderBy(e => e.Timestamp).First();
            var addresses = g.Select(e => e.SourceIp!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var failed = g.Count(e => e.EventId == 140);
            yield return new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "RDP reachable from the internet",
                Description = $"{first.Hostname} accepted {g.Count()} RDP connection(s) from {addresses.Count} public address(es)" +
                              (failed > 0 ? $", {failed} with bad credentials" : "") + $": {string.Join(", ", addresses.Take(5))}" +
                              (addresses.Count > 5 ? $" and {addresses.Count - 5} more" : ""),
                Timestamp = first.Timestamp,
                SourceIp = addresses.Count == 1 ? addresses[0] : null,
                Host = first.Hostname,
                RelatedEventIds = string.Join(",", g.Select(e => e.EventId).Distinct().OrderBy(i => i)),
                Reasoning = "RdpCoreTS logs every TCP connection to the RDP listener (131) and every bad-password attempt (140). Connections from " +
                            "routable addresses mean the listener is exposed; successful logons from these addresses would appear as separate findings.",
                Mitre = "T1133, T1110",
                Count = g.Count(),
            };
        }
    }

    private static IEnumerable<Finding> NewCredentialsLogon(List<NormalizedEvent> events) =>
        events.Where(e => e.EventId == 4624 && e.LogonType == 9 &&
                          string.Equals(e.LogonProcess, "seclogo", StringComparison.OrdinalIgnoreCase))
            .GroupBy(e => (HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant(), e.Details))
            .Select(g => new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "NewCredentials logon (runas /netonly or pass-the-hash)",
                Description = $"{g.First().TargetUserName} on {g.First().Hostname}: logon type 9 via seclogo. {g.First().Details}",
                Timestamp = g.First().Timestamp,
                User = g.First().TargetUserName,
                Host = g.First().Hostname,
                RelatedEventIds = "4624",
                Reasoning = "Type 9 logons via seclogo come from runas /netonly - and from Mimikatz sekurlsa::pth and similar pass-the-hash tooling. Check the outbound credentials and what the process did next.",
                Mitre = "T1550.002",
                Count = g.Count(),
            });

    private static IEnumerable<Finding> LocalAccountNetworkLogon(List<NormalizedEvent> events) =>
        events.Where(e => e.EventId == 4624 && e.LogonType is 3 or 10 && !e.IsNoiseAccount &&
                          !IpUtil.IsLocalOrBlank(e.SourceIp) && e.TargetDomain is not null &&
                          HostKey.Same(e.TargetDomain, e.Hostname) &&
                          (e.AuthenticationPackage?.Contains("NTLM", StringComparison.OrdinalIgnoreCase) ?? false))
            .GroupBy(e => (HostKey.Of(e.Hostname), UserKey.Bare(e.TargetUserName).ToLowerInvariant(), e.SourceIp))
            .Select(g => new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "Local account used for remote logon",
                Description = $"Local account {g.First().TargetDomain}\\{g.First().TargetUserName} logged on to {g.First().Hostname} over the network from {g.Key.SourceIp} (NTLM)",
                Timestamp = g.First().Timestamp,
                User = g.First().TargetUserName,
                SourceIp = g.Key.SourceIp,
                Host = g.First().Hostname,
                RelatedEventIds = "4624",
                Reasoning = "Network logons with a local SAM account over NTLM are how shared local-admin passwords and pass-the-hash spread laterally.",
                Mitre = "T1078.003, T1550.002",
                Count = g.Count(),
            });

    private static IEnumerable<Finding> ExplicitCredentials(List<NormalizedEvent> events)
    {
        // Logons per (host, bare user), time-ordered, to find the logon a hand-off produced.
        var logons = events.Where(e => e.EventId == 4624)
            .ToLookup(e => HostKey.Of(e.Hostname) + "|" + UserKey.Bare(e.TargetUserName).ToLowerInvariant());
        foreach (var g in events.Where(e => e.EventId == 4648 && e.SubjectUserName is not null &&
                                            !AccountClassifier.IsNoise(e.SubjectUserName) &&
                                            e.TargetUserName is not null &&
                                            !AccountKey.SameAccount(e.SubjectUserName, e.SubjectDomain, e.TargetUserName, e.TargetDomain))
                     .GroupBy(e => (HostKey.Of(e.Hostname), UserKey.Bare(e.SubjectUserName).ToLowerInvariant(),
                                    UserKey.Bare(e.TargetUserName).ToLowerInvariant(), HostKey.Of(e.TargetServer))))
        {
            var first = g.First();
            var remote = !HostKey.IsLocal(first.TargetServer, first.Hostname);
            var landed = remote
                ? logons[HostKey.Of(first.TargetServer) + "|" + UserKey.Bare(first.TargetUserName).ToLowerInvariant()]
                    .FirstOrDefault(l => AccountKey.SameAccount(l.TargetUserName, l.TargetDomain, first.TargetUserName, first.TargetDomain) &&
                                         g.Any(x => l.Timestamp >= x.Timestamp && l.Timestamp - x.Timestamp <= TimeSpan.FromMinutes(2)))
                : null;
            yield return new Finding
            {
                Severity = remote ? FindingSeverity.Medium : FindingSeverity.Low,
                RuleName = remote ? "Alternate credentials used against a remote host" : "Alternate credentials used locally (runas)",
                Description = $"{first.SubjectDomain}\\{first.SubjectUserName} on {first.Hostname} used credentials of {first.TargetDomain}\\{first.TargetUserName}" +
                              (remote ? $" for {first.TargetServer}" : "") +
                              (first.ProcessName is null ? "" : $" via {Path.GetFileName(first.ProcessName)}") +
                              (landed is null ? "" : $"; matching logon recorded on {landed.Hostname} (type {landed.LogonType})"),
                Timestamp = first.Timestamp,
                User = first.TargetUserName,
                Host = first.Hostname,
                SourceIp = first.SourceIp,
                RelatedEventIds = landed is null ? "4648" : "4648,4624",
                SessionRef = g.Select(x => x.RemoteSessionRef).FirstOrDefault(r => r is not null),
                Reasoning = "Explicit use of a different account's credentials (4648) is how admins - and attackers holding stolen credentials - pivot. Confirm the account switch was expected.",
                Mitre = "T1078",
                Count = g.Count(),
            };
        }
    }

    // ================================================================= accounts / groups

    private static IEnumerable<Finding> PrivilegedGroupChanges(List<NormalizedEvent> events)
    {
        var created = events.Where(e => e.EventId == 4720).ToList();
        var added = events.Where(e => e.EventId is 4728 or 4732 or 4756 && AccountClassifier.IsPrivilegedGroup(e.GroupName)).ToList();

        // Removals: housekeeping on its own (Medium); the add-use-remove pattern (High) when the same
        // member was added to the same group on the same host within the previous day.
        foreach (var e in events.Where(e => e.EventId is 4729 or 4733 or 4757 && AccountClassifier.IsPrivilegedGroup(e.GroupName)))
        {
            var add = added.LastOrDefault(a => HostKey.Same(a.Hostname, e.Hostname) &&
                                               string.Equals(a.GroupName, e.GroupName, StringComparison.OrdinalIgnoreCase) &&
                                               SameMemberAccount(a, e) && e.Timestamp >= a.Timestamp && e.Timestamp - a.Timestamp <= TimeSpan.FromDays(1));
            yield return new Finding
            {
                Severity = add is not null ? FindingSeverity.High : FindingSeverity.Medium,
                RuleName = add is not null ? "Privileged group membership added then removed" : "Member removed from privileged group",
                Description = $"{MemberText(e)} removed from {e.GroupName} on {e.Hostname} by {e.SubjectDomain}\\{e.SubjectUserName}" +
                              (add is null ? "" : $" ({(e.Timestamp - add.Timestamp).TotalMinutes:0} min after being added by {add.SubjectDomain}\\{add.SubjectUserName})"),
                Timestamp = e.Timestamp,
                User = e.TargetUserName,
                Host = e.Hostname,
                RelatedEventIds = add is null ? e.EventId.ToString() : $"{add.EventId},{e.EventId}",
                Reasoning = add is not null
                    ? "Granting administrative rights briefly and taking them back is how an operator - or an attacker - covers a privileged action and leaves the group looking untouched. The add is reported separately; look at what the account did in between."
                    : "Removal from an administrative group is usually housekeeping, but it also ends an attacker's access or hides an earlier grant. Check who removed whom and when the membership was granted.",
                Mitre = "T1098",
            };
        }

        foreach (var e in added)
        {
            var newAccount = created.FirstOrDefault(c =>
                SameMemberAccount(c, e) && e.Timestamp >= c.Timestamp && e.Timestamp - c.Timestamp <= TimeSpan.FromDays(1));
            var member = MemberText(e);
            yield return new Finding
            {
                Severity = newAccount is not null ? FindingSeverity.Critical : FindingSeverity.High,
                RuleName = newAccount is not null ? "New account added to privileged group" : "Member added to privileged group",
                Description = $"{member} added to {e.GroupName} on {e.Hostname} by {e.SubjectDomain}\\{e.SubjectUserName}" +
                              (newAccount is null ? "" : $" ({(e.Timestamp - newAccount.Timestamp).TotalMinutes:0} min after the account was created)"),
                Timestamp = e.Timestamp,
                User = e.TargetUserName,
                Host = e.Hostname,
                RelatedEventIds = newAccount is null ? e.EventId.ToString() : $"4720,{e.EventId}",
                Reasoning = "Adding accounts to administrative or remote-access groups grants persistence and lateral-movement rights.",
                Mitre = newAccount is not null ? "T1136, T1098" : "T1098",
            };
        }
    }

    /// <summary>
    /// Whether two account events (a 4720 creation, a group add, a group removal) concern the same
    /// account. When both carry a SID the SIDs decide: two local accounts with the same name on two
    /// hosts (backup, svc, Administrator...) are different accounts. The name is used only when a SID
    /// is missing, and then domain-aware, so HOSTA\backup is not HOSTB\backup.
    /// </summary>
    private static bool SameMemberAccount(NormalizedEvent a, NormalizedEvent b)
    {
        if (a.Sid is not null && b.Sid is not null)
            return string.Equals(a.Sid.Trim(), b.Sid.Trim(), StringComparison.OrdinalIgnoreCase);
        return AccountKey.SameAccount(a.TargetUserName, a.TargetDomain, b.TargetUserName, b.TargetDomain);
    }

    /// <summary>The member as text: its name, with the SID beside it once a name was resolved for a SID-only member.</summary>
    private static string? MemberText(NormalizedEvent e) =>
        e.TargetUserName is null ? e.Sid
            : e.Sid is null || SidResolver.IsSidNamed(e) ? e.TargetUserName : $"{e.TargetUserName} ({e.Sid})";

    private static IEnumerable<Finding> Kerberoasting(List<NormalizedEvent> events)
    {
        static bool WeakTicket(NormalizedEvent e) =>
            e.EventId == 4769 && e.IsSuccess &&
            (e.TicketEncryptionType?.Trim().ToLowerInvariant() is "0x17" or "0x18") &&
            e.ServiceName is not null && !e.ServiceName.EndsWith('$') &&
            !e.ServiceName.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase) &&
            !e.IsNoiseAccount;

        foreach (var g in events.Where(WeakTicket).GroupBy(e => (UserKey.Bare(e.TargetUserName).ToLowerInvariant(), e.SourceIp)))
        {
            var hit = DistinctInWindow(g.ToList(), e => e.ServiceName!, 3, TimeSpan.FromMinutes(10));
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.High,
                RuleName = "Possible Kerberoasting (RC4 service tickets)",
                Description = $"{hit.Value.Event.TargetUserName} from {g.Key.SourceIp} requested RC4 tickets for {hit.Value.Count} service accounts within 10 minutes",
                Timestamp = hit.Value.At,
                User = hit.Value.Event.TargetUserName,
                SourceIp = g.Key.SourceIp,
                Host = hit.Value.Event.Hostname,
                RelatedEventIds = "4769",
                Reasoning = "Bulk RC4-encrypted service ticket requests for user service accounts let an attacker crack service-account passwords offline.",
                Mitre = "T1558.003",
                Count = hit.Value.Count,
            };
        }
    }

    private IEnumerable<Finding> KerberosFanOut(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.EventId == 4769 && e.IsSuccess && !e.IsNoiseAccount &&
                                            e.ServiceName?.EndsWith('$') == true && !IpUtil.IsLocalOrBlank(e.SourceIp))
                     .GroupBy(e => e.SourceIp!))
        {
            var hit = DistinctInWindow(g.ToList(), e => e.ServiceName!, 15, _o.Window);
            if (hit is null) continue;
            yield return new Finding
            {
                Severity = FindingSeverity.Medium,
                RuleName = "Service tickets for many hosts (DC view)",
                Description = $"{g.Key} requested service tickets for {hit.Value.Count} computer accounts within {_o.Window.TotalMinutes:0} minutes",
                Timestamp = hit.Value.At,
                SourceIp = g.Key,
                User = hit.Value.Event.TargetUserName,
                Host = hit.Value.Event.Hostname,
                RelatedEventIds = "4769",
                Reasoning = "From the domain controller's log, one client obtaining tickets to many computers in a short window shows lateral movement or discovery even when the targets' logs were not collected.",
                Mitre = "T1021, T1018",
                Count = hit.Value.Count,
            };
        }
    }

    private static IEnumerable<Finding> Lockouts(List<NormalizedEvent> events) =>
        events.Where(e => e.EventId == 4740)
            .GroupBy(e => UserKey.Bare(e.TargetUserName).ToLowerInvariant())
            .Select(g => new Finding
            {
                Severity = g.Count() >= 3 ? FindingSeverity.Medium : FindingSeverity.Low,
                RuleName = "Account locked out",
                Description = $"{g.First().TargetUserName} locked out {g.Count()} time(s); caller computer(s): " +
                              string.Join(", ", g.Select(e => e.WorkstationName).Where(w => w is not null).Distinct().Take(5)),
                Timestamp = g.First().Timestamp,
                User = g.First().TargetUserName,
                Host = g.First().Hostname,
                RelatedEventIds = "4740",
                Reasoning = "Lockouts identify the computer submitting bad passwords - the place to look for a brute-force source or stale credentials.",
                Mitre = "T1110",
                Count = g.Count(),
            });

    // ================================================================= time / privilege context

    private IEnumerable<Finding> AfterHours(List<NormalizedEvent> events)
    {
        foreach (var g in events.Where(e => e.CountsAsLogonSuccess && e.EventId == 4624 && e.LogonType is 2 or 10 or 11 or 12 && !e.IsNoiseAccount)
                     .Select(e => (e, local: TimeZoneInfo.ConvertTime(e.Timestamp, ZoneFor(e.Hostname))))
                     .Where(x => IsAfterHours(x.local))
                     .GroupBy(x => (HostKey.Of(x.e.Hostname), UserKey.Bare(x.e.TargetUserName).ToLowerInvariant(), x.local.Date)))
        {
            var first = g.First();
            var weekend = _o.WeekendIsAfterHours && first.local.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday;
            var why = weekend ? "weekend" : $"outside {_o.BusinessStartHour:00}:00-{_o.BusinessEndHour:00}:00";
            yield return new Finding
            {
                Severity = FindingSeverity.Low,
                RuleName = "After-hours interactive / RDP logon",
                Description = $"{first.e.TargetUserName} logged on to {first.e.Hostname} {g.Count()} time(s) outside business hours on " +
                              $"{LocalDay(first.local)} ({why}; first at {first.local:HH:mm} {ZoneFor(first.e.Hostname).Id})",
                Timestamp = first.e.Timestamp,
                User = first.e.TargetUserName,
                SourceIp = first.e.SourceIp,
                Host = first.e.Hostname,
                RelatedEventIds = "4624",
                Reasoning = $"Interactive / RDP logon outside {_o.BusinessStartHour:00}:00-{_o.BusinessEndHour:00}:00 {ZoneFor(first.e.Hostname).Id}" +
                            (_o.WeekendIsAfterHours ? " or at the weekend" : "") + "; compare with the user's normal pattern.",
                Mitre = "T1078",
                Count = g.Count(),
            };
        }
    }

    /// <summary>"Saturday 2026-09-12" (invariant culture: the analyst's machine may run another locale).</summary>
    private static string LocalDay(DateTimeOffset local) =>
        local.ToString("dddd yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// Outside business hours: start &lt; end is the ordinary day (7-19); start &gt; end is a shift that
    /// crosses midnight (22-6 = business hours 22:00-06:00, so after hours is 06:00-22:00).
    /// </summary>
    private bool IsAfterHours(DateTimeOffset local)
    {
        if (_o.WeekendIsAfterHours && local.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday) return true;
        var h = local.Hour;
        return _o.BusinessStartHour < _o.BusinessEndHour
            ? h < _o.BusinessStartHour || h >= _o.BusinessEndHour
            : h < _o.BusinessStartHour && h >= _o.BusinessEndHour;
    }

    private static IEnumerable<Finding> PrivilegedRemoteLogons(List<NormalizedEvent> events)
    {
        var logons = new Dictionary<string, NormalizedEvent>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in events.Where(e => e.EventId == 4624 && e.LogonType is 3 or 10 && e.LogonId is not null && !e.IsNoiseAccount))
            logons[HostKey.Of(l.Hostname) + "|" + l.LogonId] = l;

        return events.Where(e => e.EventId == 4672 && e.IsPrivileged && e.LogonId is not null)
            .Select(e => logons.TryGetValue(HostKey.Of(e.Hostname) + "|" + e.LogonId, out var l) ? l : null)
            .Where(l => l is not null && !IpUtil.IsLocalOrBlank(l.SourceIp))
            .GroupBy(l => (HostKey.Of(l!.Hostname), UserKey.Bare(l.TargetUserName).ToLowerInvariant(), l.LogonType))
            .Select(g => new Finding
            {
                Severity = FindingSeverity.Low,
                RuleName = "Privileged remote logon",
                Description = $"{g.First()!.TargetUserName} logged on to {g.First()!.Hostname} with admin rights {g.Count()} time(s) " +
                              $"(type {g.Key.LogonType}) from {string.Join(", ", g.Select(x => x!.SourceIp).Distinct().Take(5))}",
                Timestamp = g.First()!.Timestamp,
                User = g.First()!.TargetUserName,
                SourceIp = g.First()!.SourceIp,
                Host = g.First()!.Hostname,
                RelatedEventIds = "4624,4672",
                Reasoning = "Remote logons that receive special privileges are administrative access; confirm the account is expected to administer this host.",
                Mitre = "T1078.002",
                Count = g.Count(),
            });
    }

    // ================================================================= window helpers

    private readonly record struct WindowHit(int Count, DateTimeOffset At, NormalizedEvent Event);

    /// <summary>First window where the number of distinct keys reaches the threshold (O(n) sliding window).</summary>
    private static WindowHit? DistinctInWindow(List<NormalizedEvent> items, Func<NormalizedEvent, string> key,
        int threshold, TimeSpan window)
    {
        var seq = items.OrderBy(e => e.Timestamp).ToList();
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var start = 0;
        for (var end = 0; end < seq.Count; end++)
        {
            var k = key(seq[end]);
            if (string.IsNullOrEmpty(k)) continue;
            counts[k] = counts.GetValueOrDefault(k) + 1;
            while (seq[end].Timestamp - seq[start].Timestamp > window)
            {
                var sk = key(seq[start]);
                if (!string.IsNullOrEmpty(sk) && counts.TryGetValue(sk, out var c))
                {
                    if (c <= 1) counts.Remove(sk); else counts[sk] = c - 1;
                }
                start++;
            }
            if (counts.Count >= threshold)
                return new WindowHit(counts.Count, seq[end].Timestamp, seq[end]);
        }
        return null;
    }

    private static WindowHit? CountInWindow(List<NormalizedEvent> items, int threshold, TimeSpan window)
    {
        var seq = items.OrderBy(e => e.Timestamp).ToList();
        var start = 0;
        for (var end = 0; end < seq.Count; end++)
        {
            while (seq[end].Timestamp - seq[start].Timestamp > window) start++;
            var n = end - start + 1;
            if (n >= threshold) return new WindowHit(n, seq[end].Timestamp, seq[end]);
        }
        return null;
    }
}
