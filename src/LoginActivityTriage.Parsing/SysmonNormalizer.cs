using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for Microsoft-Windows-Sysmon/Operational when collected: process creation (1)
/// and named-pipe create / connect (17 / 18). Process events are kept when they match a
/// remote-execution pattern or belong to a remote logon session; pipe events only when the
/// pipe is used by remote-exec tooling.
/// </summary>
public sealed class SysmonNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = new() { 1, 17, 18 };

    public IReadOnlyCollection<int> EventIds => Supported;

    public bool CanHandle(EventXmlData ev) =>
        Supported.Contains(ev.EventId) &&
        (ev.ProviderIs("Microsoft-Windows-Sysmon") || ev.ChannelContains("Sysmon"));

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev)) return null;
        var e = NormalizerBase.Envelope(ev, context, string.Empty, "Sysmon");
        NormalizerBase.SetUser(e, ev.Get("User"));
        e.ProcessName = ev.Get("Image");
        e.ProcessId = ev.Get("ProcessId");

        if (ev.EventId == 1)
        {
            e.EventType = "Process created (Sysmon)";
            e.ParentProcessName = ev.Get("ParentImage");
            e.CommandLine = ev.Get("CommandLine");
            e.LogonId = ev.Get("LogonId")?.ToLowerInvariant();
            e.Details = e.CommandLine is null ? null : NormalizerBase.Truncate(e.CommandLine, 400);
            var m = RemoteExecPatterns.ClassifyProcess(e.ProcessName, e.ParentProcessName, e.CommandLine);
            if (m is not null) NormalizerBase.Apply(e, m);
            else e.KeepOnlyIfLinked = true;
            return e;
        }

        var pipe = ev.Get("PipeName");
        var pm = RemoteExecPatterns.ClassifyPipe(pipe);
        if (pm is null) return null;
        e.EventType = ev.EventId == 17 ? "Named pipe created (Sysmon)" : "Named pipe connected (Sysmon)";
        e.RelativeTargetName = pipe;
        e.Details = NormalizerBase.Join(pipe, e.ProcessName);
        NormalizerBase.Apply(e, pm);
        return e;
    }
}
