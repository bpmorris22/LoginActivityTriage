using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for Remote Desktop artifacts, routed strictly by provider:
/// <list type="bullet">
/// <item>TerminalServices-LocalSessionManager 21/22/23/24/25/39/40/41 (session lifecycle)</item>
/// <item>TerminalServices-RemoteConnectionManager 1149 (network-level authentication succeeded)</item>
/// <item>RemoteDesktopServices-RdpCoreTS 131 (TCP connection accepted, pre-auth) / 140 (bad credentials)</item>
/// <item>TerminalServices-RDPClient 1024 / 1102 (outbound connection attempts from this host)</item>
/// </list>
/// </summary>
public sealed class TerminalServicesNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Lsm = new() { 21, 22, 23, 24, 25, 39, 40, 41 };
    private static readonly HashSet<int> Rcm = new() { 1149 };
    private static readonly HashSet<int> CoreTs = new() { 131, 140 };
    private static readonly HashSet<int> Client = new() { 1024, 1102 };
    private static readonly HashSet<int> All = Lsm.Concat(Rcm).Concat(CoreTs).Concat(Client).ToHashSet();

    private static readonly Dictionary<int, string> LsmNames = new()
    {
        [21] = "RDP/console session logon succeeded",
        [22] = "Shell start notification",
        [23] = "Session logoff succeeded",
        [24] = "Session disconnected",
        [25] = "Session reconnected",
        [39] = "Session disconnected by another session",
        [40] = "Session disconnected (reason code)",
        [41] = "Begin session arbitration",
    };

    /// <summary>Variant label for Hyper-V VM console connections (RDP client with a VM GUID target).</summary>
    public const string VmConsole = "Hyper-V VM console (VMConnect)";

    public IReadOnlyCollection<int> EventIds => All;

    public bool CanHandle(EventXmlData ev) => Family(ev) is not null;

    private static string? Family(EventXmlData ev)
    {
        if (Lsm.Contains(ev.EventId) &&
            (ev.ProviderContains("TerminalServices-LocalSessionManager") || ev.ChannelContains("LocalSessionManager")))
            return "LSM";
        if (Rcm.Contains(ev.EventId) &&
            (ev.ProviderContains("TerminalServices-RemoteConnectionManager") || ev.ChannelContains("RemoteConnectionManager")))
            return "RCM";
        if (CoreTs.Contains(ev.EventId) &&
            (ev.ProviderContains("RdpCoreTS") || ev.ChannelContains("RdpCoreTS")))
            return "CoreTS";
        if (Client.Contains(ev.EventId) &&
            (ev.ProviderContains("ClientActiveXCore") || ev.ChannelContains("RDPClient")))
            return "Client";
        return null;
    }

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        var family = Family(ev);
        if (family is null) return null;

        var e = NormalizerBase.Envelope(ev, context, string.Empty, "TerminalServices");
        switch (family)
        {
            case "LSM":
            {
                e.EventType = LsmNames[ev.EventId];
                NormalizerBase.SetUser(e, ev.GetAny("User", "Param1"));
                e.SessionId = ev.GetAny("SessionID", "Session", "TargetSession");
                // Console sessions log a LOCALISED word here ("LOCAL", "本機", "LOKAL"...), RDP logs the
                // client IP - so only a real IP address means remote.
                var rawAddress = ev.GetAny("Address", "Param3");
                var address = IpUtil.Normalize(rawAddress);
                var remote = IpUtil.IsIp(address) && !IpUtil.IsLocalOrBlank(address);
                e.SourceIp = IpUtil.IsIp(address) ? address : null;
                if (!IpUtil.IsIp(address) && rawAddress is not null) e.Details = $"Address: {rawAddress} (console / local)";
                // Console logons log Address "LOCAL"; only remote addresses are RDP. Events without an
                // address (23, 39, 40, 41) are tagged by the session builder when their SessionID
                // belongs to a remote session.
                if (remote)
                    e.Technique = RemoteTechnique.Rdp;
                if (ev.EventId == 21 && remote)
                    e.LogonType = 10;
                if (ev.EventId == 21) e.IsSuccess = true;
                if (ev.EventId == 39)
                    e.Details = $"Session {ev.Get("TargetSession")} disconnected by session {ev.Get("Source")}";
                if (ev.EventId == 40)
                    e.Details = $"Session {ev.Get("Session")} disconnected, reason {ev.Get("Reason")}";
                if (ev.EventId == 21 && !remote) e.EventType = "Console session logon succeeded";
                e.Activity = ev.EventId switch
                {
                    21 => EventActivity.Logon,
                    23 => EventActivity.Logoff,
                    24 or 39 or 40 => EventActivity.Disconnect,
                    25 => EventActivity.Reconnect,
                    _ => null,
                };
                break;
            }
            case "RCM":
                // 1149 = network-level authentication succeeded. With NLA disabled it fires before
                // any password is typed, so it is NOT a confirmed logon.
                e.EventType = "RDP connection authenticated (NLA)";
                NormalizerBase.SetUser(e, ev.GetAny("Param1", "User"), ev.GetAny("Param2", "Domain"));
                e.SourceIp = IpUtil.Normalize(ev.GetAny("Param3", "Address"));
                e.Technique = RemoteTechnique.Rdp;
                break;
            case "CoreTS":
            {
                var raw = ev.GetAny("ClientIP", "IPString", "ClientAddress") ?? FirstIpLike(ev);
                e.SourceIp = IpUtil.Normalize(raw);
                e.SourcePort = IpUtil.PortOf(raw);
                e.Technique = RemoteTechnique.Rdp;
                if (ev.EventId == 131)
                {
                    e.EventType = "RDP TCP connection accepted (pre-auth)";
                    e.Details = ev.Get("ConnType");
                }
                else
                {
                    e.EventType = "RDP connection failed: bad user name or password";
                    e.IsFailure = true;
                    e.FailureReason = "Bad user name or password (RDP)";
                }
                break;
            }
            case "Client":
            {
                // <Data Name="Name">Server Name</Data><Data Name="Value">host</Data>
                var target = ev.GetAny("Value", "ServerName", "Server") ?? ev.GetPositional(1);
                e.TargetServer = target;
                e.Technique = RemoteTechnique.Rdp;
                // Hyper-V VMConnect drives the same RDP ActiveX control with the VM's GUID as "server".
                e.TechniqueDetail = Guid.TryParse(target, out _) ? VmConsole : "RDP client";
                e.IsOutbound = true;
                e.EventType = ev.EventId == 1024
                    ? "Outbound RDP connection attempt"
                    : "Outbound RDP multi-transport connection";
                e.Details = target is null ? null : $"To {target}";
                break;
            }
        }
        return e;
    }

    private static string? FirstIpLike(EventXmlData ev) =>
        ev.AllValues.Select(v => v?.Trim()).FirstOrDefault(v => v is not null && IpUtil.IsIp(IpUtil.Normalize(v)));
}
