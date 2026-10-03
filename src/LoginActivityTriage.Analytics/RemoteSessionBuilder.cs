using System.Text.RegularExpressions;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Analytics;

/// <summary>
/// Stitches individual events into remote-access sessions per host:
/// <list type="number">
/// <item>Service execution (PsExec family, Impacket psexec / smbexec, remote service creation)</item>
/// <item>PowerShell Remoting / WinRS</item>
/// <item>WMI and DCOM execution</item>
/// <item>Remote scheduled tasks (incl. Impacket atexec)</item>
/// <item>Executable drops on admin shares not explained by the above</item>
/// <item>RDP sessions (NLA auth, logon, reconnects, disconnects, logoff)</item>
/// <item>Outbound activity from this host (psexec.exe, mstsc, WinRM client, remote WMI...)</item>
/// </list>
/// Joins use the logon session id where the event carries one, otherwise the nearest network
/// logon on the same host within a short window. Each event is assigned to at most one session.
/// </summary>
public sealed class RemoteSessionBuilder
{
    private static readonly TimeSpan ServiceCluster = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan ShellCluster = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan LogonLookBack = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan RdpJoin = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan RdpMaxIdle = TimeSpan.FromHours(24);

    private static readonly Regex UncTarget = new(@"\\\\(?<h>[A-Za-z0-9][A-Za-z0-9\.\-_]*)", RegexOptions.Compiled);
    private static readonly Regex MstscTarget = new(@"/v:?\s*""?(?<h>[^\s"":]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex ComputerNameArg = new(@"-(ComputerName|cn)\s+""?(?<h>[^\s"",;]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex NodeArg = new(@"/node:""?(?<h>[^\s""]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex SchtasksArg = new(@"\s/s\s+""?(?<h>[^\s""]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex WinrsArg = new(@"-r(emote)?:""?(?<h>[^\s""]+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public List<RemoteSession> Build(IEnumerable<NormalizedEvent> events)
    {
        var sessions = new List<RemoteSession>();
        var pairs = new List<(RemoteSession Session, string Address, string Name)>();
        foreach (var hostGroup in events
                     .Where(e => e.Timestamp != DateTimeOffset.MinValue)
                     .GroupBy(e => HostKey.Of(e.Hostname)))
        {
            var ctx = new HostContext(hostGroup.OrderBy(e => e.Timestamp).ThenBy(e => e.RecordId ?? 0).ToList());
            sessions.AddRange(ServiceExecution(ctx));
            sessions.AddRange(Shells(ctx, new[] { RemoteTechnique.PsRemoting, RemoteTechnique.WinRs }));
            sessions.AddRange(Shells(ctx, new[] { RemoteTechnique.Wmi, RemoteTechnique.Dcom }));
            sessions.AddRange(RemoteTasks(ctx));
            sessions.AddRange(AdminShareDrops(ctx));
            sessions.AddRange(Rdp(ctx));
            sessions.AddRange(Outbound(ctx, pairs));
        }
        Corroborate(pairs);

        var ordered = sessions.OrderBy(s => s.Start).ThenBy(s => s.Host).ToList();
        for (var i = 0; i < ordered.Count; i++)
        {
            var s = ordered[i];
            s.Id = i + 1;
            foreach (var e in s.Events) e.RemoteSessionRef = s.Id;
        }
        return ordered;
    }

    // ------------------------------------------------------------------ host context

    private sealed class HostContext
    {
        /// <summary>The host's events, ordered by time (time-window lookups binary-search this list).</summary>
        public List<NormalizedEvent> Events { get; }
        public HashSet<NormalizedEvent> Assigned { get; } = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<string, List<NormalizedEvent>> _logons = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<NormalizedEvent>> _logoffs = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Ordinal of every 4624, so two events of the same logon share one identity key.</summary>
        private readonly Dictionary<NormalizedEvent, int> _logonOrdinal = new(ReferenceEqualityComparer.Instance);
        public List<NormalizedEvent> NetworkLogons { get; } = new();
        /// <summary>Boot times on this host, ordered.</summary>
        public List<DateTimeOffset> Boots { get; } = new();

        public HostContext(List<NormalizedEvent> events)
        {
            Events = events;
            foreach (var e in events)
            {
                if (e.EventId == 4624)
                {
                    _logonOrdinal[e] = _logonOrdinal.Count;
                    if (e.LogonId is not null) Add(_logons, e.LogonId, e);
                    if (e.LinkedLogonId is not null) Add(_logons, e.LinkedLogonId, e);
                    if (e.LogonType == 3 && !e.IsNoiseAccount) NetworkLogons.Add(e);
                }
                else if (e.EventId is 4634 or 4647 && e.LogonId is not null)
                {
                    Add(_logoffs, e.LogonId, e);
                }
                if (BootTimes.IsBoot(e)) Boots.Add(e.Timestamp);
            }
        }

        private static void Add(Dictionary<string, List<NormalizedEvent>> d, string k, NormalizedEvent e)
        {
            if (!d.TryGetValue(k, out var l)) d[k] = l = new List<NormalizedEvent>();
            l.Add(e);
        }

        public bool BootBetween(DateTimeOffset from, DateTimeOffset to) => BootTimes.Between(Boots, from, to);

        /// <summary>
        /// The logon a logon id refers to at <paramref name="at"/>: the most recent 4624 with that id
        /// at or before it, unless the host rebooted in between (ids are unique only per boot).
        /// </summary>
        public NormalizedEvent? LogonFor(string? logonId, DateTimeOffset at)
        {
            if (logonId is null || !_logons.TryGetValue(logonId, out var l)) return null;
            var logon = l.Where(x => x.Timestamp <= at.AddSeconds(5)).OrderByDescending(x => x.Timestamp).FirstOrDefault();
            return logon is not null && !BootBetween(logon.Timestamp, at) ? logon : null;
        }

        /// <summary>Stable key of a resolved logon (the 4624 itself), for partitioning events by session.</summary>
        public string? LogonKey(NormalizedEvent? logon) =>
            logon is not null && _logonOrdinal.TryGetValue(logon, out var n) ? "logon#" + n : null;

        public NormalizedEvent? LogoffFor(NormalizedEvent? logon)
        {
            if (logon?.LogonId is null) return null;
            NormalizedEvent? best = null;
            foreach (var id in new[] { logon.LogonId, logon.LinkedLogonId })
            {
                if (id is null || !_logoffs.TryGetValue(id, out var l)) continue;
                var c = l.Where(x => x.Timestamp >= logon.Timestamp && !BootBetween(logon.Timestamp, x.Timestamp))
                    .OrderBy(x => x.Timestamp).FirstOrDefault();
                if (c is not null && (best is null || c.Timestamp > best.Timestamp)) best = c;
            }
            return best is not null && best.Timestamp - logon.Timestamp <= TimeSpan.FromDays(7) ? best : null;
        }

        /// <summary>Nearest non-noise network logon around a moment, preferring a matching IP, then user.</summary>
        public NormalizedEvent? NearestNetworkLogon(DateTimeOffset at, TimeSpan before, TimeSpan after,
            string? ip = null, string? user = null)
        {
            var c = new List<NormalizedEvent>();
            for (var i = LowerBound(NetworkLogons, at - before); i < NetworkLogons.Count && NetworkLogons[i].Timestamp <= at + after; i++)
                c.Add(NetworkLogons[i]);
            if (c.Count == 0) return null;
            return c.OrderByDescending(l => ip is not null && l.SourceIp == ip)
                .ThenByDescending(l => user is not null && UserKey.Same(l.TargetUserName, user))
                .ThenBy(l => Math.Abs((l.Timestamp - at).TotalSeconds))
                .First();
        }

        public IEnumerable<NormalizedEvent> Unassigned(Func<NormalizedEvent, bool> predicate) =>
            Events.Where(e => !Assigned.Contains(e) && predicate(e));

        /// <summary>Events in [from, to] (assigned or not), by binary search on the time-ordered list.</summary>
        public IEnumerable<NormalizedEvent> Window(DateTimeOffset from, DateTimeOffset to, Func<NormalizedEvent, bool> predicate)
        {
            for (var i = LowerBound(Events, from); i < Events.Count && Events[i].Timestamp <= to; i++)
                if (predicate(Events[i])) yield return Events[i];
        }

        /// <summary>Unassigned events in [from, to].</summary>
        public IEnumerable<NormalizedEvent> Between(DateTimeOffset from, DateTimeOffset to, Func<NormalizedEvent, bool> predicate) =>
            Window(from, to, e => !Assigned.Contains(e) && predicate(e));

        private static int LowerBound(List<NormalizedEvent> list, DateTimeOffset t)
        {
            int lo = 0, hi = list.Count;
            while (lo < hi) { var mid = (lo + hi) / 2; if (list[mid].Timestamp < t) lo = mid + 1; else hi = mid; }
            return lo;
        }
    }

    // ------------------------------------------------------------------ identity partitioning

    /// <summary>Logon ids of SYSTEM / LOCAL SERVICE / NETWORK SERVICE: shared by every service process, never an identity.</summary>
    private static readonly HashSet<string> SystemLogonIds = new(StringComparer.OrdinalIgnoreCase) { "0x3e7", "0x3e4", "0x3e5" };

    /// <summary>The logon session an event belongs to (resolved 4624, else the raw id), or null when it carries none.</summary>
    private static string? IdentityOf(HostContext ctx, NormalizedEvent m)
    {
        foreach (var id in new[] { m.LogonId, m.SubjectLogonId })
        {
            if (id is null || SystemLogonIds.Contains(id)) continue;
            return ctx.LogonKey(ctx.LogonFor(id, m.Timestamp)) ?? "id:" + id;
        }
        return null;
    }

    /// <summary>
    /// Groups anchor events into sessions. Events that carry a logon session are partitioned by it
    /// first and then split by time, so two users' simultaneous sessions never merge. Events without
    /// one (WinRM 91, 7045, Sysmon pipes...) join the single identified cluster they overlap in time
    /// - with the same user when they name one - and otherwise form their own time clusters.
    /// </summary>
    private static List<(string? Key, List<NormalizedEvent> Events)> ClusterByIdentity(
        HostContext ctx, List<NormalizedEvent> anchors, TimeSpan gap)
    {
        var keyed = new List<(string? Key, List<NormalizedEvent> Events)>();
        var unkeyed = new List<NormalizedEvent>();
        foreach (var g in anchors.GroupBy(m => IdentityOf(ctx, m)))
        {
            if (g.Key is null) { unkeyed.AddRange(g); continue; }
            foreach (var c in Cluster(g.ToList(), gap)) keyed.Add((g.Key, c));
        }

        var spans = keyed.Select(k => (Start: k.Events[0].Timestamp, End: k.Events[^1].Timestamp, k.Events))
            .OrderBy(s => s.Start).ToList();
        var maxSpan = spans.Count == 0 ? TimeSpan.Zero : spans.Max(s => s.End - s.Start);
        var leftover = new List<NormalizedEvent>();
        foreach (var m in unkeyed)
        {
            var user = m.TargetUserName is not null && !AccountClassifier.IsNoise(m.TargetUserName) ? m.TargetUserName : null;
            List<NormalizedEvent>? only = null;
            var matches = 0;
            // Spans are ordered by start: begin at the last one starting by m + gap and walk back only
            // while a span could still reach m (starts within maxSpan + gap before it).
            int lo = 0, hi = spans.Count;
            while (lo < hi) { var mid = (lo + hi) / 2; if (spans[mid].Start <= m.Timestamp + gap) lo = mid + 1; else hi = mid; }
            for (var i = lo - 1; i >= 0 && spans[i].Start >= m.Timestamp - gap - maxSpan; i--)
            {
                var s = spans[i];
                if (m.Timestamp < s.Start - gap || m.Timestamp > s.End + gap) continue;
                if (user is not null && s.Events.Any(x => x.TargetUserName is not null && !AccountClassifier.IsNoise(x.TargetUserName) &&
                                                          !UserKey.Same(x.TargetUserName, user))) continue;
                only = s.Events;
                if (++matches > 1) break;
            }
            if (matches == 1) only!.Add(m);
            else leftover.Add(m);
        }

        return keyed.Select(k => (k.Key, k.Events.OrderBy(e => e.Timestamp).ToList()))
            .Concat(Cluster(leftover, gap).Select(c => ((string?)null, c)))
            .OrderBy(c => c.Item2[0].Timestamp)
            .ToList();
    }

    // ------------------------------------------------------------------ 1. service execution

    private static IEnumerable<RemoteSession> ServiceExecution(HostContext ctx)
    {
        bool IsSupport(NormalizedEvent e) =>
            !e.IsOutbound && e.Technique is RemoteTechnique.AdminShare or RemoteTechnique.RemoteServiceControl;

        // Plain service installs become remote when tied to a network logon (4697 subject) or
        // preceded by remote SCM / admin-share access.
        foreach (var e in ctx.Events.Where(e => e.EventId is 7045 or 4697 && e.Technique is null))
        {
            var viaLogon = ctx.LogonFor(e.SubjectLogonId ?? e.LogonId, e.Timestamp);
            var viaScm = ctx.Window(e.Timestamp - TimeSpan.FromSeconds(60), e.Timestamp + TimeSpan.FromSeconds(5), IsSupport).Any();
            if (viaLogon is { LogonType: 3 } || viaScm)
            {
                e.Technique = RemoteTechnique.ServiceInstall;
                e.TechniqueDetail ??= "Service created remotely";
            }
        }

        var anchors = ctx.Unassigned(e => !e.IsOutbound &&
            (e.Technique == RemoteTechnique.PsExec || e.Technique == RemoteTechnique.ServiceInstall)).ToList();

        foreach (var (key, cluster) in ClusterByIdentity(ctx, anchors, ServiceCluster))
        {
            var start = cluster[0].Timestamp;
            var end = cluster[^1].Timestamp;
            // Admin-share / SCM access of ANOTHER logon session is someone else's run.
            var support = ctx.Between(start - LogonLookBack, end + TimeSpan.FromSeconds(60),
                s => IsSupport(s) && (key is null || IdentityOf(ctx, s) is not { } sk || sk == key)).ToList();
            var members = cluster.Concat(support).ToList();

            var ip = members.Select(m => m.SourceIp).FirstOrDefault(i => !IpUtil.IsLocalOrBlank(i));
            var logon = members.Select(m => ctx.LogonFor(m.SubjectLogonId ?? m.LogonId, m.Timestamp))
                            .FirstOrDefault(l => l is { LogonType: 3 })
                        ?? ctx.NearestNetworkLogon(start, LogonLookBack, TimeSpan.FromSeconds(5), ip);

            var service = cluster.FirstOrDefault(m => m.EventId is 7045 or 4697);
            var technique = cluster.Any(m => m.Technique == RemoteTechnique.PsExec)
                ? RemoteTechnique.PsExec : RemoteTechnique.ServiceInstall;
            var variant = service?.TechniqueDetail ?? cluster.Select(m => m.TechniqueDetail).FirstOrDefault(v => v is not null);

            var s = Make(ctx, technique, variant, "Inbound", members, logon);
            s.Detail = service is null ? null : $"Service {service.ServiceName}: {service.ServiceFileName}";
            var pipes = members.Where(m => m.EventId is 5145 or 17 or 18 && m.RelativeTargetName is not null)
                .Select(m => m.RelativeTargetName!).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
            s.Evidence = Evidence(
                service is null ? null : $"service '{service.ServiceName}' installed ({service.EventId})",
                pipes.Count > 0 ? $"pipe/file {string.Join(", ", pipes)}" : null,
                members.Any(m => m.EventId is 4688 or 1) ? "process lineage" : null,
                LogonText(logon));
            s.Confidence = logon is not null && (service is not null || pipes.Count > 0) ? "High" : "Medium";
            yield return s;
        }
    }

    // ------------------------------------------------------------------ 2/3. shells (WinRM, WMI, DCOM)

    private static IEnumerable<RemoteSession> Shells(HostContext ctx, string[] techniques)
    {
        var anchors = ctx.Unassigned(e => !e.IsOutbound && e.Technique is not null && techniques.Contains(e.Technique)).ToList();
        foreach (var (_, cluster) in ClusterByIdentity(ctx, anchors, ShellCluster))
        {
            var start = cluster[0].Timestamp;
            var user = cluster.Where(m => m.EventId is 169 or 4103 or 32850)
                           .Select(m => m.TargetUserName).FirstOrDefault(u => u is not null)
                       ?? cluster.Select(m => m.TargetUserName).FirstOrDefault(u => u is not null && !AccountClassifier.IsNoise(u));
            var logon = cluster.Select(m => ctx.LogonFor(m.LogonId ?? m.SubjectLogonId, m.Timestamp))
                            .FirstOrDefault(l => l is { LogonType: 3 })
                        ?? ctx.NearestNetworkLogon(start, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30), null, user);

            var technique = cluster.GroupBy(m => m.Technique).OrderByDescending(g => g.Count()).First().Key!;
            var variant = cluster.Select(m => m.TechniqueDetail).FirstOrDefault(v => v?.Contains("Impacket") == true)
                          ?? cluster.Select(m => m.TechniqueDetail).FirstOrDefault(v => v is not null);
            var s = Make(ctx, technique, variant, "Inbound", cluster, logon);
            if (user is not null && (s.User is null || AccountClassifier.IsNoise(s.User))) s.User = UserKey.Bare(user);
            var uris = cluster.Where(m => m.EventId == 91 && m.Details is not null).Select(m => m.Details!).Distinct().ToList();
            s.Detail = uris.Count > 0 ? string.Join("; ", uris) : variant;
            s.Evidence = Evidence(
                string.Join(", ", cluster.Select(m => $"{m.EventId}").Distinct().Take(8)) is var ids && ids.Length > 0 ? $"events {ids}" : null,
                cluster.Any(m => m.EventId == 169) ? $"WinRM authenticated {user} ({cluster.First(m => m.EventId == 169).AuthenticationPackage})" : null,
                LogonText(logon));
            s.Confidence = logon is not null ? "High" : "Medium";
            yield return s;
        }
    }

    // ------------------------------------------------------------------ 4. scheduled tasks

    private static IEnumerable<RemoteSession> RemoteTasks(HostContext ctx)
    {
        foreach (var task in ctx.Unassigned(e => e.EventId is 4698 or 4702 && !e.IsOutbound).ToList())
        {
            var logon = ctx.LogonFor(task.SubjectLogonId ?? task.LogonId, task.Timestamp);
            var remote = logon is { LogonType: 3 } || task.TechniqueDetail == "Impacket atexec";
            if (!remote) continue;
            task.Technique = RemoteTechnique.ScheduledTask;
            task.TechniqueDetail ??= "Task registered over the network";
            var support = ctx.Between(task.Timestamp - TimeSpan.FromSeconds(60), task.Timestamp + TimeSpan.FromMinutes(2),
                e => e.Technique == RemoteTechnique.ScheduledTask || (e.EventId == 4699 && e.TaskName == task.TaskName)).ToList();
            var s = Make(ctx, RemoteTechnique.ScheduledTask, task.TechniqueDetail, "Inbound",
                new[] { task }.Concat(support).ToList(), logon);
            s.Detail = $"Task {task.TaskName}";
            s.Commands ??= task.CommandLine;
            s.Evidence = Evidence($"task '{task.TaskName}' created by {task.SubjectDomain}\\{task.SubjectUserName}", LogonText(logon));
            s.Confidence = logon is not null ? "High" : "Medium";
            yield return s;
        }
    }

    // ------------------------------------------------------------------ 5. admin-share drops

    private static IEnumerable<RemoteSession> AdminShareDrops(HostContext ctx)
    {
        var anchors = ctx.Unassigned(e => e.EventId == 5145 && e.Technique == RemoteTechnique.AdminShare).ToList();
        foreach (var (key, cluster) in ClusterByIdentity(ctx, anchors, TimeSpan.FromMinutes(5)))
        {
            var start = cluster[0].Timestamp;
            var mounts = ctx.Between(start - LogonLookBack, cluster[^1].Timestamp,
                e => e.EventId == 5140 && e.Technique == RemoteTechnique.AdminShare &&
                     (key is null || IdentityOf(ctx, e) is not { } mk || mk == key)).ToList();
            var members = cluster.Concat(mounts).ToList();
            var logon = ctx.LogonFor(cluster[0].SubjectLogonId ?? cluster[0].LogonId, start)
                        ?? ctx.NearestNetworkLogon(start, LogonLookBack, TimeSpan.FromSeconds(5), cluster[0].SourceIp);
            var s = Make(ctx, RemoteTechnique.AdminShare, "Write access to executable / script on admin share", "Inbound", members, logon);
            s.Detail = string.Join("; ", cluster.Select(m => $"{m.ShareName}\\{m.RelativeTargetName}").Distinct().Take(5));
            s.Evidence = Evidence($"{cluster.Count} admin-share file access event(s)", LogonText(logon));
            s.Confidence = logon is not null ? "Medium" : "Low";
            yield return s;
        }
    }

    // ------------------------------------------------------------------ 6. RDP

    private sealed class RdpBuild
    {
        public List<NormalizedEvent> Members { get; } = new();
        public HashSet<string> LogonIds { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> SessionIds { get; } = new(StringComparer.OrdinalIgnoreCase);
        public string UserKey = string.Empty;
        public DateTimeOffset LastSeen;
        public bool HasLogon;
        public bool Closed;
        public bool Disconnected;
    }

    private static IEnumerable<RemoteSession> Rdp(HostContext ctx)
    {
        var builds = new List<RdpBuild>();
        // Builds by user / LSM session id / logon id, in creation order (the last is the most recent).
        var byUser = new Dictionary<string, List<RdpBuild>>(StringComparer.OrdinalIgnoreCase);
        var bySession = new Dictionary<string, List<RdpBuild>>(StringComparer.OrdinalIgnoreCase);
        var byLogon = new Dictionary<string, List<RdpBuild>>(StringComparer.OrdinalIgnoreCase);

        static void Index(Dictionary<string, List<RdpBuild>> d, string k, RdpBuild b)
        {
            if (!d.TryGetValue(k, out var l)) d[k] = l = new List<RdpBuild>();
            if (l.Count == 0 || !ReferenceEquals(l[^1], b)) l.Add(b);
        }

        static RdpBuild? Latest(Dictionary<string, List<RdpBuild>> d, string? k, Func<RdpBuild, bool> ok)
        {
            if (k is null || !d.TryGetValue(k, out var l)) return null;
            for (var i = l.Count - 1; i >= 0; i--) if (ok(l[i])) return l[i];
            return null;
        }

        // A session does not survive a reboot, whatever ids or idle time say.
        RdpBuild? OpenFor(string user, DateTimeOffset at) =>
            Latest(byUser, user, b => !b.Closed && at - b.LastSeen <= RdpMaxIdle && !ctx.BootBetween(b.LastSeen, at));

        RdpBuild Start(string user, NormalizedEvent e)
        {
            var b = new RdpBuild { UserKey = user, LastSeen = e.Timestamp };
            builds.Add(b);
            Index(byUser, user, b);
            return b;
        }

        void Add(RdpBuild b, NormalizedEvent e)
        {
            b.Members.Add(e);
            b.LastSeen = e.Timestamp > b.LastSeen ? e.Timestamp : b.LastSeen;
            foreach (var id in new[] { e.LogonId, e.LinkedLogonId })
                if (id is not null && b.LogonIds.Add(id)) Index(byLogon, id, b);
            if (e.SessionId is not null && e.EventId is 21 or 22 or 25 && b.SessionIds.Add(e.SessionId)) Index(bySession, e.SessionId, b);
            ctx.Assigned.Add(e);
        }

        static bool IsAuth(NormalizedEvent e) => e.EventId == 1149 || (e.EventId == 4624 && e.LogonType is 10 or 12);

        // The logon was a reconnect's authentication: a 4778 / LSM 25 followed its 4624 within the
        // join window, and the session's own logon (the 4778's id) is a different one.
        static bool IsReconnectAuth(RdpBuild b, string? logonId)
        {
            var auth = b.Members.LastOrDefault(m => m.EventId == 4624 && m.LogonId == logonId);
            return auth is not null && b.Members.Any(m => m.EventId is 4778 or 25 && m.LogonId != logonId &&
                                                          m.Timestamp >= auth.Timestamp && m.Timestamp - auth.Timestamp <= RdpJoin);
        }

        foreach (var e in ctx.Events.Where(e => !ctx.Assigned.Contains(e) && !e.IsOutbound))
        {
            var user = UserKey.Bare(e.TargetUserName).ToLowerInvariant();
            var remoteLsm = e.Technique == RemoteTechnique.Rdp && e.EventId is 21 or 22 or 24 or 25;

            if (IsAuth(e) || e.EventId == 4778 && e.Technique == RemoteTechnique.Rdp)
            {
                if (user.Length == 0) continue;
                var open = OpenFor(user, e.Timestamp);
                // Auth right after a disconnect = reconnect; auth within the join window = same logon.
                if (open is null || !(open.Disconnected || e.Timestamp - open.LastSeen <= RdpJoin || e.EventId == 4778))
                    open = Start(user, e);
                open.Disconnected = false;
                Add(open, e);
                if (e.EventId == 4624) open.HasLogon = true;
            }
            else if (remoteLsm)
            {
                if (user.Length == 0) continue;
                var open = OpenFor(user, e.Timestamp);
                if (e.EventId == 21)
                {
                    // A session logon joins a pending auth (1149 / 4624) that has no LSM logon yet.
                    if (open is null || open.Members.Any(m => m.EventId == 21) && e.Timestamp - open.LastSeen > RdpJoin)
                        open = Start(user, e);
                    open.HasLogon = true;
                }
                open ??= Start(user, e);
                if (e.EventId == 24) open.Disconnected = true;
                if (e.EventId == 25) open.Disconnected = false;
                Add(open, e);
            }
            else if (e.EventId is 23 or 39 or 40 or 41 && e.SessionId is not null)
            {
                // LSM 23 is the session-manager record of a logoff the Security log may have closed
                // the build with a moment earlier (4647 then 23): accept it within a minute.
                var b = Latest(bySession, e.SessionId, x => e.Timestamp >= x.Members[0].Timestamp &&
                                                           !ctx.BootBetween(x.LastSeen, e.Timestamp) &&
                                                           (!x.Closed || e.EventId == 23 && e.Timestamp - x.LastSeen <= TimeSpan.FromMinutes(1)));
                if (b is null) continue; // console session
                e.Technique ??= RemoteTechnique.Rdp;
                Add(b, e);
                if (e.EventId == 23) b.Closed = true;
                if (e.EventId is 39 or 40) b.Disconnected = true;
            }
            else if (e.EventId is 4634 or 4647 or 4779 or 4672 or 4688 or 1 && e.LogonId is not null)
            {
                // Same boot only; after logoff only the duplicate logoff bookkeeping (split-token
                // 4634 pairs, 4647 + 4634) within a minute - never processes or a later session.
                var b = Latest(byLogon, e.LogonId, x => e.Timestamp >= x.Members[0].Timestamp &&
                                                       !ctx.BootBetween(x.LastSeen, e.Timestamp) &&
                                                       (!x.Closed || e.EventId is 4634 or 4647 && e.Timestamp - x.LastSeen <= TimeSpan.FromMinutes(1)));
                if (b is null) continue;
                Add(b, e);
                // A reconnect authenticates with a short-lived type-10 logon (logged off minutes later)
                // while the session runs on under its original logon (the 4778's id): only the
                // session's own logoff closes it.
                if (e.EventId is 4634 or 4647 && !IsReconnectAuth(b, e.LogonId)) b.Closed = true;
                if (e.EventId == 4779) b.Disconnected = true;
            }
        }

        foreach (var b in builds.Where(b => b.Members.Count > 0))
        {
            var first = b.Members[0];
            // Pre-auth TCP connections (131) from the same IP just before the session.
            var ip = b.Members.Select(m => m.SourceIp).FirstOrDefault(i => !IpUtil.IsLocalOrBlank(i));
            if (ip is not null)
                foreach (var c in ctx.Between(first.Timestamp - TimeSpan.FromSeconds(120), first.Timestamp,
                             x => x.EventId == 131 && x.SourceIp == ip).ToList())
                {
                    b.Members.Insert(0, c);
                    ctx.Assigned.Add(c);
                }

            var logon = b.Members.FirstOrDefault(m => m.EventId == 4624);
            var s = Make(ctx, RemoteTechnique.Rdp, null, "Inbound", b.Members, logon, assign: false);
            s.LogonType ??= 10;
            s.SourceIp = string.Join("; ", b.Members.Select(m => m.SourceIp)
                .Where(i => !IpUtil.IsLocalOrBlank(i)).Distinct(StringComparer.OrdinalIgnoreCase));
            if (s.SourceIp.Length == 0) s.SourceIp = null;
            s.SourceHost ??= b.Members.Select(m => m.WorkstationName).FirstOrDefault(w => w is not null);
            var reconnects = b.Members.Count(m => m.EventId is 25 or 4778);
            var disconnects = b.Members.Count(m => m.EventId is 24 or 4779);
            var admin = b.Members.Any(m => m.EventId == 4672);
            s.Detail = Evidence(
                b.SessionIds.Count > 0 ? $"session {string.Join(",", b.SessionIds)}" : null,
                reconnects > 0 ? $"{reconnects} reconnect(s)" : null,
                disconnects > 0 ? $"{disconnects} disconnect(s)" : null,
                admin ? "admin rights (4672)" : null,
                b.Closed ? "logged off" : "no logoff recorded");
            s.Evidence = Evidence(
                b.Members.Any(m => m.EventId == 1149) ? "NLA auth (1149)" : null,
                b.HasLogon ? "session logon (4624 type 10 / LSM 21)" : "no session-logon event in the logs",
                LogonText(logon));
            s.Confidence = b.HasLogon ? "High" : "Low";
            yield return s;
        }
    }

    // ------------------------------------------------------------------ 7. outbound

    /// <summary>How a 4648 credential hand-off fits an outbound connection.</summary>
    private enum CredFit { None, Tentative, Exact }

    /// <summary>Processes that log the client-side 4648 for each technique.</summary>
    private static readonly Dictionary<string, string[]> ClientProcesses = new()
    {
        [RemoteTechnique.Rdp] = new[] { "lsass.exe", "mstsc.exe", "CredentialUIBroker.exe" }, // CredSSP / NLA
        [RemoteTechnique.PsExec] = new[] { "psexec.exe", "psexec64.exe", "paexec.exe" },
        [RemoteTechnique.PsRemoting] = new[] { "powershell.exe", "pwsh.exe", "powershell_ise.exe", "winrs.exe" },
        [RemoteTechnique.WinRs] = new[] { "winrs.exe", "powershell.exe", "pwsh.exe" },
        [RemoteTechnique.Wmi] = new[] { "wmic.exe", "powershell.exe", "pwsh.exe" },
        [RemoteTechnique.ScheduledTask] = new[] { "schtasks.exe", "at.exe" },
        [RemoteTechnique.RemoteServiceControl] = new[] { "sc.exe" },
    };

    /// <summary>
    /// Exact: the hand-off names the connection's destination. Tentative: one side names an address
    /// and the other a host name (the usual RDP case - the client logs the IP, CredSSP's lsass 4648
    /// the server name) and the hand-off came from that technique's client process. A hand-off
    /// classified as another technique, or naming a different destination of the same kind, is not
    /// this connection's.
    /// </summary>
    private static CredFit Fit(NormalizedEvent cred, string technique, string? target)
    {
        if (cred.Technique is not null && cred.Technique != technique) return CredFit.None;
        if (target is not null && HostKey.Same(cred.TargetServer, target)) return CredFit.Exact;
        if (target is not null && IpUtil.IsIp(target) == IpUtil.IsIp(cred.TargetServer)) return CredFit.None;
        var process = Path.GetFileName(cred.ProcessName ?? "");
        return cred.Technique == technique ||
               (ClientProcesses.TryGetValue(technique, out var p) && p.Contains(process, StringComparer.OrdinalIgnoreCase))
            ? CredFit.Tentative : CredFit.None;
    }

    private static IEnumerable<RemoteSession> Outbound(HostContext ctx, List<(RemoteSession Session, string Address, string Name)> pairs)
    {
        var outbound = ctx.Unassigned(e => e.IsOutbound && e.Technique is not null).ToList();
        // Client-log groups (RDP 1024, WinRM 6, process starts) go first so they can claim the
        // matching 4648; a 4648 left over afterwards still forms its own session.
        foreach (var group in outbound.GroupBy(e => (e.Technique!, HostKey.Of(TargetOf(e))))
                     .OrderBy(g => g.All(e => e.EventId == 4648) ? 1 : 0))
        {
            var technique = group.Key.Item1;
            // Every RDP client "connecting to" event (1024) is a separate attempt; its follow-up
            // events (1102 multi-transport, 1029) belong to it. Other techniques cluster by time.
            var clusters = technique == RemoteTechnique.Rdp
                ? SplitAt(group.OrderBy(e => e.Timestamp).ToList(), e => e.EventId == 1024)
                : Cluster(group.ToList(), TimeSpan.FromMinutes(5));
            foreach (var raw in clusters)
            {
                var cluster = raw.Where(e => !ctx.Assigned.Contains(e)).ToList();
                if (cluster.Count == 0) continue;
                var start = cluster[0].Timestamp;
                var members = cluster.ToList();
                var target = cluster.Select(TargetOf).FirstOrDefault(t => t is not null);

                // The credential hand-off for the connection: a 4648 by a real account seconds after
                // the attempt (CredSSP / NLA, PsExec -u, WinRM -Credential) that fits its technique and
                // destination. A name-for-address match is accepted only when every fitting candidate
                // names the same server - two candidate servers means there is no way to tell.
                var candidates = ctx.Between(start.AddSeconds(-5), start.AddSeconds(45),
                        e => e.EventId == 4648 && e.TargetServer is not null &&
                             !HostKey.IsLocal(e.TargetServer, e.Hostname) &&
                             !AccountClassifier.IsNoise(e.SubjectUserName))
                    .Select(e => (Event: e, Fit: Fit(e, technique, target)))
                    .Where(x => x.Fit != CredFit.None).OrderBy(x => x.Event.Timestamp).ToList();
                var exact = candidates.Where(x => x.Fit == CredFit.Exact).Select(x => x.Event).ToList();
                var tentative = exact.Count == 0 && candidates.Count > 0 &&
                                candidates.Select(x => HostKey.Of(x.Event.TargetServer)).Distinct().Count() == 1;
                var cred = exact.Count > 0 ? exact.Where(c => HostKey.Same(c.TargetServer, exact[0].TargetServer)).ToList()
                    : tentative ? candidates.Select(x => x.Event).ToList()
                    : new List<NormalizedEvent>();
                members.AddRange(cred);

                var s = Make(ctx, technique, cluster.Select(m => m.TechniqueDetail).FirstOrDefault(v => v is not null),
                    "Outbound", members, null);
                s.TargetHost = target;
                var c0 = cred.FirstOrDefault();
                if (c0 is not null)
                {
                    s.User = UserKey.Bare(c0.SubjectUserName);
                    s.Domain = c0.SubjectDomain;
                    s.CredentialsUsed = c0.TargetUserName is null ? null
                        : (c0.TargetDomain is null ? c0.TargetUserName : $"{c0.TargetDomain}\\{c0.TargetUserName}");
                    if (!string.Equals(c0.TargetServer, s.TargetHost, StringComparison.OrdinalIgnoreCase))
                        s.TargetHostName = c0.TargetServer;
                }
                else
                {
                    s.User = cluster.Select(m => m.SubjectUserName ?? m.TargetUserName)
                        .FirstOrDefault(u => u is not null && !AccountClassifier.IsNoise(u)) ?? s.User;
                }
                s.Detail = s.TargetHost is null ? null
                    : $"To {s.TargetHost}{(s.TargetHostName is null ? "" : $" ({s.TargetHostName})")}" +
                      (s.CredentialsUsed is null ? "" : $" with {s.CredentialsUsed} credentials");
                s.Evidence = Evidence(
                    string.Join(", ", cluster.Select(m => m.EventType).Distinct().Take(4)),
                    c0 is null ? null : $"4648 at {c0.Timestamp.UtcDateTime:HH:mm:ss}Z: {c0.SubjectDomain}\\{c0.SubjectUserName} used {s.CredentialsUsed} for {c0.TargetServer}",
                    tentative ? $"the connection event names {target ?? "no destination"}, the hand-off names {c0!.TargetServer}: matched by time and " +
                                $"{Path.GetFileName(c0.ProcessName ?? c0.Technique ?? "technique")} only" : null);
                // High needs the destination itself to match; a name-for-address match is Medium until
                // other connections corroborate the same pairing (see Build).
                s.Confidence = s.TargetHost is null ? "Low" : (c0 is not null && !tentative ? "High" : "Medium");
                if (tentative && s.TargetHost is not null && s.TargetHostName is not null)
                    pairs.Add((s, HostKey.Of(s.TargetHost), HostKey.Of(s.TargetHostName)));
                yield return s;
            }
        }
    }

    /// <summary>
    /// An address-to-name pairing inferred from timing (Tentative) is confirmed when the same pairing
    /// recurs on two or more connections and neither the address nor the name is ever paired with
    /// anything else; a conflicting pairing is withdrawn.
    /// </summary>
    private static void Corroborate(List<(RemoteSession Session, string Address, string Name)> pairs)
    {
        var namesOf = pairs.ToLookup(p => p.Address, p => p.Name, StringComparer.OrdinalIgnoreCase);
        var addressesOf = pairs.ToLookup(p => p.Name, p => p.Address, StringComparer.OrdinalIgnoreCase);
        foreach (var (s, address, name) in pairs)
        {
            var names = namesOf[address].Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var addresses = addressesOf[name].Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (names.Count == 1 && addresses.Count == 1)
            {
                var n = namesOf[address].Count();
                if (n < 2) continue;
                s.Confidence = "High";
                s.Evidence = Evidence(s.Evidence, $"{s.TargetHost} = {s.TargetHostName} corroborated by {n} connections");
            }
            else
            {
                s.Evidence = Evidence(s.Evidence, $"name withdrawn: {s.TargetHost} is also paired with {string.Join(", ", names.Where(x => !x.Equals(name, StringComparison.OrdinalIgnoreCase)))}" +
                                                  $"{(addresses.Count > 1 ? $" and {s.TargetHostName} with {string.Join(", ", addresses.Where(x => !x.Equals(address, StringComparison.OrdinalIgnoreCase)))}" : "")}");
                s.TargetHostName = null;
                s.Detail = s.TargetHost is null ? s.Detail : $"To {s.TargetHost}" + (s.CredentialsUsed is null ? "" : $" with {s.CredentialsUsed} credentials");
            }
        }
    }

    /// <summary>Starts a new group at every item matching <paramref name="isStart"/>.</summary>
    private static IEnumerable<List<NormalizedEvent>> SplitAt(List<NormalizedEvent> ordered, Func<NormalizedEvent, bool> isStart)
    {
        var current = new List<NormalizedEvent>();
        foreach (var e in ordered)
        {
            if (current.Count > 0 && isStart(e))
            {
                yield return current;
                current = new List<NormalizedEvent>();
            }
            current.Add(e);
        }
        if (current.Count > 0) yield return current;
    }

    private static string? TargetOf(NormalizedEvent e)
    {
        if (!string.IsNullOrWhiteSpace(e.TargetServer)) return e.TargetServer;
        var cmd = e.CommandLine;
        if (string.IsNullOrWhiteSpace(cmd)) return null;
        foreach (var re in new[] { MstscTarget, ComputerNameArg, NodeArg, SchtasksArg, WinrsArg, UncTarget })
        {
            var m = re.Match(cmd);
            if (m.Success) return m.Groups["h"].Value.Trim('"', '\'');
        }
        return null;
    }

    // ------------------------------------------------------------------ helpers

    private static IEnumerable<List<NormalizedEvent>> Cluster(List<NormalizedEvent> items, TimeSpan gap)
    {
        var ordered = items.OrderBy(e => e.Timestamp).ToList();
        var current = new List<NormalizedEvent>();
        foreach (var e in ordered)
        {
            if (current.Count > 0 && e.Timestamp - current[^1].Timestamp > gap)
            {
                yield return current;
                current = new List<NormalizedEvent>();
            }
            current.Add(e);
        }
        if (current.Count > 0) yield return current;
    }

    private static RemoteSession Make(HostContext ctx, string technique, string? variant, string direction,
        IList<NormalizedEvent> members, NormalizedEvent? logon, bool assign = true)
    {
        var all = new List<NormalizedEvent>(members);
        var logoff = ctx.LogoffFor(logon);
        if (logon is not null && !all.Contains(logon) && !ctx.Assigned.Contains(logon)) all.Add(logon);
        if (logoff is not null && !all.Contains(logoff) && !ctx.Assigned.Contains(logoff)) all.Add(logoff);

        // Processes that ran inside the linked logon session - which ends at logoff or at the next boot.
        if (logon?.LogonId is not null)
        {
            var until = logoff?.Timestamp ?? all.Max(m => m.Timestamp).AddHours(1);
            if (BootTimes.After(ctx.Boots, logon.Timestamp) is { } boot && boot < until) until = boot;
            foreach (var p in ctx.Between(logon.Timestamp, until,
                         p => p.EventId is 4688 or 1 && (p.LogonId == logon.LogonId || p.SubjectLogonId == logon.LogonId)))
                all.Add(p);
        }

        all = all.Distinct().OrderBy(m => m.Timestamp).ToList();
        if (assign) foreach (var m in all) ctx.Assigned.Add(m);
        else foreach (var m in all) ctx.Assigned.Add(m);

        var user = logon?.TargetUserName
                   ?? all.Select(m => m.TargetUserName).FirstOrDefault(u => u is not null && !AccountClassifier.IsNoise(u))
                   ?? all.Select(m => m.SubjectUserName).FirstOrDefault(u => u is not null && !AccountClassifier.IsNoise(u));
        var domain = logon?.TargetDomain
                     ?? all.FirstOrDefault(m => m.TargetUserName is not null && UserKey.Same(m.TargetUserName, user))?.TargetDomain;
        var commands = all.Where(m => m.CommandLine is not null && m.EventId is 4688 or 1 or 4103 or 4698 or 4702)
            .Select(m => m.CommandLine!.Trim()).Distinct().Take(25).ToList();

        // Last resort: the SID an event was logged under (7045 installer, WinRM 91 user).
        user ??= all.Select(m => m.Sid).FirstOrDefault(sid => sid is not null && !AccountClassifier.IsWellKnownServiceSid(sid));

        var s = new RemoteSession
        {
            Technique = technique,
            Variant = variant,
            Direction = direction,
            Host = all.Select(m => m.Hostname).FirstOrDefault(h => h is not null),
            Start = all.Min(m => m.Timestamp),
            End = all.Max(m => m.Timestamp),
            User = user is null ? null : UserKey.Bare(user),
            Domain = domain,
            SourceIp = logon?.SourceIp ?? all.Select(m => m.SourceIp).FirstOrDefault(i => !IpUtil.IsLocalOrBlank(i)),
            SourceHost = logon?.WorkstationName ?? all.Select(m => m.WorkstationName).FirstOrDefault(w => w is not null),
            LogonId = logon?.LogonId,
            LogonType = logon?.LogonType,
            AuthPackage = logon?.AuthenticationPackage,
            Commands = commands.Count == 0 ? null : string.Join(" | ", commands.Select(c => c.Length > 300 ? c[..300] + "…" : c)),
            EventCount = all.Count,
            EventIds = string.Join(",", all.Select(m => m.EventId).Distinct().OrderBy(i => i)),
        };
        s.Events.AddRange(all);
        return s;
    }

    private static string? LogonText(NormalizedEvent? logon) =>
        logon is null ? null
            : $"logon {logon.LogonId} type {logon.LogonType} as {logon.TargetDomain}\\{logon.TargetUserName}" +
              (logon.SourceIp is null ? "" : $" from {logon.SourceIp}") +
              (logon.AuthenticationPackage is null ? "" : $" ({logon.AuthenticationPackage})");

    private static string? Evidence(params string?[] parts)
    {
        var list = parts.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
        return list.Count == 0 ? null : string.Join("; ", list);
    }
}
