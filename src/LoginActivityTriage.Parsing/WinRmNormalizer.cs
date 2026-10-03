using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for Microsoft-Windows-WinRM/Operational (PowerShell Remoting / WinRS transport).
/// <list type="bullet">
/// <item>Target side: 91 (WSMan shell created, resource URI), 169 (user authenticated + mechanism), 142 (operation failed)</item>
/// <item>Source side: 6 (WSMan session created, connection string names the target), 161 (client could not connect / authenticate)</item>
/// </list>
/// </summary>
public sealed class WinRmNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = new() { 6, 91, 142, 161, 169 };

    public IReadOnlyCollection<int> EventIds => Supported;

    public bool CanHandle(EventXmlData ev) =>
        Supported.Contains(ev.EventId) &&
        (ev.ProviderIs("Microsoft-Windows-WinRM") || ev.ChannelContains("WinRM"));

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev)) return null;
        var e = NormalizerBase.Envelope(ev, context, string.Empty, "WinRM");
        e.Sid = ev.UserSid;

        switch (ev.EventId)
        {
            case 6:
            {
                var conn = ev.GetAny("connection", "Connection") ?? ev.GetPositional(0);
                e.TargetServer = TargetOf(conn);
                e.EventType = "WSMan session created (client)";
                e.Details = conn;
                if (HostKey.IsLocal(e.TargetServer, ev.Computer)) return e; // local WinRM use
                NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.PsRemoting, "WinRM client session", true));
                break;
            }
            case 91:
            {
                var uri = ev.GetAny("resourceUri", "ResourceUri") ?? ev.GetPositional(0);
                e.EventType = "WSMan shell created (server)";
                e.Details = uri;
                var isCmdShell = uri?.Contains("/shell/cmd", StringComparison.OrdinalIgnoreCase) == true;
                NormalizerBase.Apply(e, isCmdShell
                    ? new RemoteExecMatch(RemoteTechnique.WinRs, "WinRS cmd shell")
                    : new RemoteExecMatch(RemoteTechnique.PsRemoting, ShellName(uri)));
                break;
            }
            case 169:
            {
                var user = ev.GetAny("username", "userName", "User") ?? ev.GetPositional(0);
                NormalizerBase.SetUser(e, user);
                e.AuthenticationPackage = ev.GetAny("authenticationMechanism", "AuthenticationMechanism") ?? ev.GetPositional(1);
                e.EventType = "WinRM user authenticated (server)";
                e.IsSuccess = true;
                NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.PsRemoting, "WinRM authentication"));
                break;
            }
            case 142:
            {
                var op = ev.GetAny("operationName", "OperationName") ?? ev.GetPositional(0);
                var code = ev.GetAny("errorCode", "ErrorCode") ?? ev.GetPositional(1);
                e.EventType = "WSMan operation failed";
                e.Status = code;
                e.Details = $"{op} failed, error {code}";
                break;
            }
            case 161:
                // Logged by any local WinRM client (management agents poll constantly) and names no
                // target, so on its own it is context, not evidence of outbound remoting. It is a
                // client connectivity error, not an account's authentication failure, so it is not
                // flagged as a failure (it must not feed failure counts or brute-force rules).
                e.EventType = "WinRM client could not connect / authenticate";
                e.Details = NormalizerBase.Join(ev.AllValues.ToArray());
                break;
        }
        return e;
    }

    /// <summary>"server01.contoso.local/wsman?PSVersion=5.1" → "server01.contoso.local".</summary>
    internal static string? TargetOf(string? connection)
    {
        if (string.IsNullOrWhiteSpace(connection)) return null;
        var c = connection.Trim();
        var scheme = c.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) c = c[(scheme + 3)..];
        var cut = c.IndexOfAny(new[] { '/', '?' });
        if (cut >= 0) c = c[..cut];
        var colon = c.LastIndexOf(':');
        if (colon > 0 && !c.Contains("::")) c = c[..colon];
        return c.Length == 0 ? null : c;
    }

    private static string ShellName(string? uri)
    {
        if (uri is null) return "WSMan shell";
        var last = uri.TrimEnd('/');
        last = last[(last.LastIndexOf('/') + 1)..];
        return $"WSMan shell ({last})";
    }
}
