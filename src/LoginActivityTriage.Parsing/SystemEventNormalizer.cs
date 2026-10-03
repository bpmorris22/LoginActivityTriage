using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for the System log: service installs (7045), state changes of known remote-exec
/// services (7036), start-type changes of remote-access services (7040), log clearing (104), the
/// host's time zone (6013) and power events - boot (6005), clean shutdown (6006), unexpected
/// shutdown (6008, Kernel-Power 41) and who / what initiated a shutdown or restart (User32 1074).
/// Routed by provider: "Service Control Manager", "EventLog", "Microsoft-Windows-Eventlog",
/// "User32" and "Microsoft-Windows-Kernel-Power".
/// </summary>
public sealed class SystemEventNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = new() { 41, 104, 1074, 6005, 6006, 6008, 6013, 7036, 7040, 7045 };
    private static readonly System.Text.RegularExpressions.Regex BiasAndName =
        new(@"^\s*(?<bias>-?\d{1,4})\s+(?<name>.+?)\s*$", System.Text.RegularExpressions.RegexOptions.Compiled);
    // 1074's shutdown type is localised ("restart", "重新啟動", "Neu starten"...).
    private static readonly System.Text.RegularExpressions.Regex RestartWord =
        new(@"restart|reboot|重新啟動|重新启动|neu ?start|red[ée]marr|reinici|riavvi|再起動|다시 시작",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex PowerOffWord =
        new(@"power ?off|shut ?down|電源關閉|电源关闭|關機|关机|電源オフ|シャットダウン|전원 끄기|herunterfahr|ausschalt|arr[êe]t|apagad|apagar|spegni",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);
    private static readonly System.Text.RegularExpressions.Regex HostSuffix =
        new(@"\s*\([^()\\]+\)\s*$", System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Services whose start-type change matters for remote access.</summary>
    private static readonly HashSet<string> RemoteAccessServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinRM", "Windows Remote Management (WS-Management)", "RemoteRegistry", "Remote Registry",
        "TermService", "Remote Desktop Services", "sshd", "OpenSSH SSH Server", "WMI", "Winmgmt",
        "Windows Management Instrumentation",
    };

    public IReadOnlyCollection<int> EventIds => Supported;

    public bool CanHandle(EventXmlData ev) =>
        Supported.Contains(ev.EventId) &&
        (ev.EventId switch
        {
            104 => ev.ProviderIs("Microsoft-Windows-Eventlog"),
            6005 or 6006 or 6008 or 6013 => ev.ProviderIs("EventLog"),
            1074 => ev.ProviderIs("User32") || ev.ProviderContains("User32"),
            41 => ev.ProviderContains("Kernel-Power"),
            _ => ev.ProviderIs("Service Control Manager") || ev.ProviderContains("Service Control Manager"),
        });

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev)) return null;
        var e = NormalizerBase.Envelope(ev, context, WindowsEventCatalog.DescribeSystem(ev.EventId), "System");
        e.Sid = ev.UserSid;

        switch (ev.EventId)
        {
            case 7045:
                e.ServiceName = ev.GetAny("ServiceName", "param1") ?? ev.GetPositional(0);
                e.ServiceFileName = ev.GetAny("ImagePath", "param2") ?? ev.GetPositional(1);
                e.ServiceType = ev.GetAny("ServiceType", "param3");
                e.ServiceStartType = ev.GetAny("StartType", "param4");
                e.ServiceAccount = ev.GetAny("AccountName", "param5");
                var m = RemoteExecPatterns.ClassifyService(e.ServiceName, e.ServiceFileName);
                if (m is not null && (m.Value.Technique != RemoteTechnique.ServiceInstall || m.Value.Variant is not null))
                    NormalizerBase.Apply(e, m);
                e.Details = NormalizerBase.Join(e.ServiceName, e.ServiceFileName, e.ServiceAccount);
                break;

            case 7036:
            {
                var name = ev.GetAny("param1") ?? ev.GetPositional(0);
                if (!RemoteExecPatterns.IsKnownRemoteExecServiceName(name)) return null;
                e.ServiceName = name;
                var state = ev.GetAny("param2") ?? ev.GetPositional(1);
                e.Details = $"{name} entered the {state} state";
                NormalizerBase.Apply(e, RemoteExecPatterns.ClassifyService(name, null));
                break;
            }

            case 7040:
            {
                var name = ev.GetAny("param1") ?? ev.GetPositional(0);
                if (name is null || !RemoteAccessServices.Contains(name)) return null;
                e.ServiceName = name;
                e.Details = $"{name} start type changed from {ev.GetAny("param2")} to {ev.GetAny("param3")}";
                break;
            }

            case 6013:
            {
                // Daily "system uptime" event. Its last data item is "<bias minutes> <zone name>",
                // e.g. "-480 Taipei Standard Time" (the name is localised). Bias = UTC - local, so
                // the host's UTC offset is its negation. Used for per-host after-hours evaluation.
                var last = Enumerable.Range(0, ev.PositionalCount).Select(i => ev.GetPositional(i))
                    .LastOrDefault(v => v is not null && BiasAndName.IsMatch(v));
                if (last is null) return null;
                var bm = BiasAndName.Match(last);
                var offset = -int.Parse(bm.Groups["bias"].Value, System.Globalization.CultureInfo.InvariantCulture);
                e.EventType = "System uptime / time zone";
                e.UtcOffsetMinutes = offset;
                e.Details = $"{TimeZoneUtil.FixedOffset(offset).Id} ({bm.Groups["name"].Value}); uptime {ev.GetPositional(4)} s";
                break;
            }

            case 6005:
                e.Activity = EventActivity.Boot;
                break;
            case 6006:
                e.Activity = EventActivity.Shutdown;
                break;
            case 6008:
            {
                // Positional: time and date of the previous (unexpected) shutdown, localised.
                var when = NormalizerBase.Join(ev.GetAny("param1") ?? ev.GetPositional(0), ev.GetAny("param2") ?? ev.GetPositional(1));
                e.Activity = EventActivity.UnexpectedShutdown;
                e.Details = when is null ? "The previous shutdown was unexpected" : $"The previous shutdown at {when.Replace(" | ", " ")} (local time) was unexpected";
                break;
            }
            case 41:
            {
                var bug = ev.GetAny("BugcheckCode");
                e.Activity = EventActivity.UnexpectedShutdown;
                e.Details = bug is not null && bug != "0"
                    ? $"Rebooted after a bugcheck (BugcheckCode {bug})"
                    : "Rebooted without a clean shutdown: no bugcheck - power loss, forced reset or hang";
                break;
            }
            case 1074:
            {
                // param1 process "(HOST)", param3 reason, param4 code, param5 type, param6 comment, param7 user.
                var process = ev.GetAny("param1") ?? ev.GetPositional(0);
                var type = ev.GetAny("param5") ?? ev.GetPositional(4);
                var user = ev.GetAny("param7") ?? ev.GetPositional(6);
                e.ProcessName = process is null ? null : HostSuffix.Replace(process, "");
                var (u, d) = UserKey.Split(user);
                e.SubjectUserName = u;
                e.SubjectDomain = d;
                // A real account is the subject of the timeline row; SYSTEM shows from the SID.
                if (!AccountClassifier.IsNoise(u, null)) { e.TargetUserName = u; e.TargetDomain = d; }
                e.Activity = type is not null && RestartWord.IsMatch(type) ? EventActivity.Restart
                    : type is not null && PowerOffWord.IsMatch(type) ? EventActivity.Shutdown
                    : EventActivity.ShutdownOrRestart;
                e.Details = NormalizerBase.Join(type, ev.GetAny("param3") ?? ev.GetPositional(2),
                    ev.GetAny("param6") ?? ev.GetPositional(5), e.ProcessName is null ? null : $"by {e.ProcessName}");
                break;
            }
            case 104:
                e.TargetUserName = ev.Get("SubjectUserName");
                e.TargetDomain = ev.Get("SubjectDomainName");
                e.SubjectUserName = e.TargetUserName;
                e.SubjectDomain = e.TargetDomain;
                e.Technique = RemoteTechnique.LogCleared;
                e.Details = $"{ev.Get("Channel") ?? "An event"} log cleared";
                break;
        }
        return e;
    }
}
