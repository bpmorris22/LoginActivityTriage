using System.Text.RegularExpressions;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for PowerShell Remoting evidence on the TARGET host. Only remoting-related records
/// are kept; ordinary local PowerShell activity is ignored.
/// <list type="bullet">
/// <item>"Windows PowerShell" (provider PowerShell) 400 / 403: engine started / stopped with
/// HostName=ServerRemoteHost or HostApplication=wsmprovhost.exe</item>
/// <item>Microsoft-Windows-PowerShell/Operational 4103 (module logging) executed in a
/// ServerRemoteHost, and 32850 (server remote session created)</item>
/// </list>
/// </summary>
public sealed class PowerShellNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Classic = new() { 400, 403 };
    private static readonly HashSet<int> Operational = new() { 4103, 32850 };
    private static readonly HashSet<int> All = Classic.Concat(Operational).ToHashSet();

    private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.Compiled;
    private static readonly Regex ClassicHostName = new(@"HostName=(?<v>[^\r\n]+)", Opt);
    private static readonly Regex ClassicHostApp = new(@"HostApplication=(?<v>[^\r\n]+)", Opt);
    private static readonly Regex CtxHostName = new(@"Host Name\s*=\s*(?<v>[^\r\n]+)", Opt);
    private static readonly Regex CtxHostApp = new(@"Host Application\s*=\s*(?<v>[^\r\n]+)", Opt);
    private static readonly Regex CtxUser = new(@"(?<!Connected )User\s*=\s*(?<v>[^\r\n]+)", Opt);
    private static readonly Regex CtxConnectedUser = new(@"Connected User\s*=\s*(?<v>[^\r\n]+)", Opt);
    private static readonly Regex CtxCommand = new(@"Command Name\s*=\s*(?<v>[^\r\n]+)", Opt);
    private static readonly Regex UserNameColon = new(@"UserName:\s*(?<v>\S+)", Opt);

    public IReadOnlyCollection<int> EventIds => All;

    public bool CanHandle(EventXmlData ev) =>
        (Classic.Contains(ev.EventId) && (ev.ProviderIs("PowerShell") || ev.ChannelIs("Windows PowerShell"))) ||
        (Operational.Contains(ev.EventId) &&
         (ev.ProviderIs("Microsoft-Windows-PowerShell") || ev.ChannelContains("PowerShell/Operational")));

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev)) return null;
        var e = NormalizerBase.Envelope(ev, context, string.Empty, "PowerShell");
        e.Sid = ev.UserSid;
        var text = string.Join("\n", ev.AllValues);

        if (Classic.Contains(ev.EventId))
        {
            var hostName = Grab(ClassicHostName, text);
            var hostApp = Grab(ClassicHostApp, text);
            if (!IsRemote(hostName, hostApp)) return null;
            e.EventType = ev.EventId == 400
                ? "PowerShell engine started (remote session)"
                : "PowerShell engine stopped (remote session)";
            e.ProcessName = hostApp;
            e.Details = NormalizerBase.Join($"HostName={hostName}", hostApp);
            NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.PsRemoting, "PowerShell ServerRemoteHost"));
            return e;
        }

        if (ev.EventId == 4103)
        {
            var ctx = ev.Get("ContextInfo") ?? text;
            var hostName = Grab(CtxHostName, ctx);
            var hostApp = Grab(CtxHostApp, ctx);
            if (!IsRemote(hostName, hostApp)) return null;
            var user = Grab(CtxConnectedUser, ctx) ?? Grab(CtxUser, ctx);
            NormalizerBase.SetUser(e, user);
            e.ProcessName = hostApp;
            e.EventType = "PowerShell command in remote session";
            e.CommandLine = NormalizerBase.Truncate(ev.Get("Payload") ?? Grab(CtxCommand, ctx) ?? string.Empty, 1000);
            e.Details = e.CommandLine;
            NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.PsRemoting, "PowerShell module logging (ServerRemoteHost)"));
            return e;
        }

        // 32850: server remote session created
        NormalizerBase.SetUser(e, Grab(UserNameColon, text));
        e.EventType = "PowerShell server remote session created";
        e.Details = NormalizerBase.Truncate(text.Replace('\n', ' '), 300);
        NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.PsRemoting, "PowerShell remoting protocol"));
        return e;
    }

    private static bool IsRemote(string? hostName, string? hostApp) =>
        (hostName?.Contains("ServerRemoteHost", StringComparison.OrdinalIgnoreCase) ?? false) ||
        (hostApp?.Contains("wsmprovhost", StringComparison.OrdinalIgnoreCase) ?? false);

    private static string? Grab(Regex re, string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var m = re.Match(text);
        if (!m.Success) return null;
        var v = m.Groups["v"].Value.Trim();
        return v.Length == 0 ? null : v;
    }
}
