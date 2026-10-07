using System.Text.RegularExpressions;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Normaliser for the Security log: logon / logoff / explicit credentials / special privileges,
/// process creation, service and scheduled-task creation, account and group changes, Kerberos and
/// NTLM validation, RDP window-station reconnects, admin-share access and audit-log clearing.
///
/// Routed by provider (Microsoft-Windows-Security-Auditing) or channel (Security) — never by
/// event ID alone.
/// </summary>
public sealed class SecurityEventNormalizer : IEventNormalizer
{
    private static readonly HashSet<int> Supported = WindowsEventCatalog.SecurityEventIds.ToHashSet();
    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);
    private static readonly Regex CommonName = new(@"^CN=(?<cn>(\\,|[^,])+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public IReadOnlyCollection<int> EventIds => Supported;

    public bool CanHandle(EventXmlData ev) =>
        Supported.Contains(ev.EventId) &&
        (ev.ProviderIs("Microsoft-Windows-Security-Auditing") || ev.ChannelIs("Security") ||
         (ev.Provider is null && ev.Channel is null));

    public NormalizedEvent? Normalize(EventXmlData ev, NormalizationContext context)
    {
        if (!CanHandle(ev)) return null;

        var e = NormalizerBase.Envelope(ev, context, WindowsEventCatalog.DescribeSecurity(ev.EventId), "Security");
        e.SubjectUserName = ev.Get("SubjectUserName");
        e.SubjectDomain = ev.Get("SubjectDomainName");
        e.SubjectLogonId = NonZeroLogonId(ev.Get("SubjectLogonId"));
        e.ProcessName = ev.Get("ProcessName");
        e.ProcessId = ev.Get("ProcessId");
        e.SourceIp = IpUtil.Normalize(ev.Get("IpAddress"));
        e.SourcePort = NonZeroPort(ev.Get("IpPort"));

        switch (ev.EventId)
        {
            case 4624:
            case 4625:
                Logon(e, ev);
                break;
            case 4634:
            case 4647:
                SetTarget(e, ev);
                e.LogonId = NonZeroLogonId(ev.Get("TargetLogonId"));
                e.LogonType = ev.GetInt("LogonType");
                e.LogonTypeDescription = e.LogonType is null ? null : LogonTypeCatalog.Describe(e.LogonType);
                if (e.LogonType is 10 or 12) e.Technique = RemoteTechnique.Rdp;
                break;
            case 4648:
                ExplicitCredentials(e, ev);
                break;
            case 4672:
                e.TargetUserName = e.SubjectUserName;
                e.TargetDomain = e.SubjectDomain;
                e.Sid = ev.Get("SubjectUserSid");
                e.LogonId = e.SubjectLogonId;
                e.PrivilegeList = Collapse(ev.Get("PrivilegeList"));
                e.ElevatedToken = true;
                // Describes the logon recorded by its 4624; not a separate successful logon.
                break;
            case 4688:
                ProcessCreated(e, ev);
                break;
            case 4697:
                ActorIsUser(e, ev);
                e.ServiceName = ev.Get("ServiceName");
                e.ServiceFileName = ev.Get("ServiceFileName");
                e.ServiceType = ev.Get("ServiceType");
                e.ServiceStartType = ev.Get("ServiceStartType");
                e.ServiceAccount = ev.Get("ServiceAccount");
                ApplyServiceClassification(e);
                e.Details = NormalizerBase.Join(e.ServiceName, e.ServiceFileName, e.ServiceAccount);
                break;
            case 4698:
            case 4699:
            case 4702:
                ActorIsUser(e, ev);
                e.TaskName = ev.Get("TaskName");
                e.CommandLine = RemoteExecPatterns.TaskCommandLine(ev.GetAny("TaskContent", "TaskContentNew"));
                var task = RemoteExecPatterns.ClassifyTask(e.CommandLine);
                if (task.Variant is not null) NormalizerBase.Apply(e, task);
                e.Details = NormalizerBase.Join(e.TaskName, e.CommandLine);
                break;
            case 4720:
            case 4722:
            case 4723:
            case 4724:
            case 4725:
            case 4726:
                SetTarget(e, ev);
                e.Sid = ev.Get("TargetSid") ?? e.Sid;
                e.Details = e.SubjectUserName is null ? null : $"By {e.SubjectDomain}\\{e.SubjectUserName}";
                break;
            case 4740:
                e.TargetUserName = ev.Get("TargetUserName");
                e.Sid = ev.Get("TargetSid");
                // 4740 stores the CALLER computer in TargetDomainName.
                e.WorkstationName = ev.Get("TargetDomainName");
                e.Details = e.WorkstationName is null ? null : $"Caller computer: {e.WorkstationName}";
                e.IsFailure = true;
                e.FailureReason = "Account locked out";
                break;
            case 4728:
            case 4732:
            case 4756:
            case 4729:
            case 4733:
            case 4757:
                GroupMember(e, ev);
                break;
            case 4781:
                // Account renamed: the row is about the account under its NEW name; the old name is kept in Details.
                e.TargetUserName = ev.Get("NewTargetUserName") ?? ev.Get("TargetUserName");
                e.TargetDomain = ev.Get("TargetDomainName") ?? e.SubjectDomain;
                e.Sid = ev.Get("TargetSid");
                e.Details = NormalizerBase.Join(
                    ev.Get("OldTargetUserName") is { } old ? $"Renamed from {old}" : null,
                    e.SubjectUserName is null ? null : $"By {e.SubjectDomain}\\{e.SubjectUserName}");
                break;
            case 4768:
            case 4769:
            case 4771:
                Kerberos(e, ev);
                break;
            case 4776:
                SetUser(e, ev.Get("TargetUserName"));
                e.WorkstationName = ev.Get("Workstation");
                e.AuthenticationPackage = "NTLM";
                e.Status = ev.Get("Status");
                if (FailureReasonCatalog.IsZero(e.Status)) e.IsSuccess = true;
                else
                {
                    e.IsFailure = true;
                    e.FailureReason = FailureReasonCatalog.Describe(e.Status, null);
                }
                break;
            case 4778:
            case 4779:
                SetUser(e, ev.Get("AccountName"), ev.Get("AccountDomain"));
                e.LogonId = NonZeroLogonId(ev.Get("LogonID"));
                e.WorkstationName = ev.Get("ClientName");
                var client = IpUtil.Normalize(ev.Get("ClientAddress"));
                e.SourceIp = IpUtil.IsIp(client) ? client : null;
                var sessionName = ev.Get("SessionName");
                e.Details = sessionName;
                if (sessionName?.StartsWith("RDP", StringComparison.OrdinalIgnoreCase) == true ||
                    (IpUtil.IsIp(client) && !IpUtil.IsLocalOrBlank(client)))
                    e.Technique = RemoteTechnique.Rdp;
                break;
            case 5140:
            case 5145:
                if (!ShareAccess(e, ev)) return null;
                break;
            case 1102:
                e.TargetUserName = e.SubjectUserName;
                e.TargetDomain = e.SubjectDomain;
                e.LogonId = e.SubjectLogonId;
                e.Technique = RemoteTechnique.LogCleared;
                e.Details = "Security log cleared";
                break;
        }

        e.Activity = ev.EventId switch
        {
            4624 => EventActivity.Logon,
            4625 => EventActivity.LogonFailed,
            4634 or 4647 => EventActivity.Logoff,
            4778 => EventActivity.Reconnect,
            4779 => EventActivity.Disconnect,
            4608 => EventActivity.Boot,
            4609 or 1100 => EventActivity.Shutdown,
            _ => null,
        };
        return e;
    }

    private static void Logon(NormalizedEvent e, EventXmlData ev)
    {
        SetTarget(e, ev);
        var logonType = ev.GetInt("LogonType");
        e.LogonType = logonType;
        e.LogonTypeDescription = logonType is null ? null : LogonTypeCatalog.Describe(logonType);
        e.LogonId = NonZeroLogonId(ev.Get("TargetLogonId"));
        e.LinkedLogonId = NonZeroLogonId(ev.Get("TargetLinkedLogonId"));
        e.WorkstationName = ev.Get("WorkstationName");
        e.AuthenticationPackage = ev.GetAny("AuthenticationPackageName", "LmPackageName");
        e.LogonProcess = ev.Get("LogonProcessName");
        e.ElevatedToken = ParseYesNo(ev.Get("ElevatedToken"));
        e.ImpersonationLevel = Impersonation(ev.Get("ImpersonationLevel"));
        if (logonType is 10 or 12) e.Technique = RemoteTechnique.Rdp;

        var lm = ev.Get("LmPackageName");
        var details = new List<string?>
        {
            lm is not null && lm.Contains("V1", StringComparison.OrdinalIgnoreCase) ? "NTLM V1" : null,
            ParseYesNo(ev.Get("RestrictedAdminMode")) == true ? "Restricted Admin mode" : null,
            ParseYesNo(ev.Get("VirtualAccount")) == true ? "Virtual account" : null,
        };
        var outUser = ev.Get("TargetOutboundUserName");
        if (outUser is not null)
            details.Add($"Outbound credentials: {ev.Get("TargetOutboundDomainName")}\\{outUser}");
        e.Details = NormalizerBase.Join(details.ToArray());

        if (ev.EventId == 4624)
        {
            e.IsSuccess = true;
        }
        else
        {
            e.IsFailure = true;
            e.Status = ev.Get("Status");
            e.SubStatus = ev.Get("SubStatus");
            e.FailureReason = FailureReasonCatalog.Describe(e.Status, e.SubStatus);
        }
    }

    private static void ExplicitCredentials(NormalizedEvent e, EventXmlData ev)
    {
        // Target = credentials that were used; Subject = who used them.
        e.TargetUserName = ev.Get("TargetUserName");
        e.TargetDomain = ev.Get("TargetDomainName");
        e.LogonId = e.SubjectLogonId;
        e.TargetServer = ev.Get("TargetServerName");
        var info = ev.Get("TargetInfo");
        e.Details = NormalizerBase.Join(
            e.SubjectUserName is null ? null : $"Used by {e.SubjectDomain}\\{e.SubjectUserName}",
            info is null ? null : $"SPN/target: {info}");

        if (HostKey.IsLocal(e.TargetServer, ev.Computer)) return;

        // Outbound: classify by the SPN service class or the calling process.
        var spn = info ?? string.Empty;
        var proc = e.ProcessName ?? string.Empty;
        RemoteExecMatch? m =
            proc.EndsWith("psexec.exe", StringComparison.OrdinalIgnoreCase) || proc.EndsWith("psexec64.exe", StringComparison.OrdinalIgnoreCase)
                ? new(RemoteTechnique.PsExec, "Sysinternals PsExec (client, explicit credentials)", true)
            : spn.StartsWith("TERMSRV/", StringComparison.OrdinalIgnoreCase) || proc.EndsWith("mstsc.exe", StringComparison.OrdinalIgnoreCase)
                ? new(RemoteTechnique.Rdp, "RDP client (explicit credentials)", true)
            : spn.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) || spn.StartsWith("WSMAN/", StringComparison.OrdinalIgnoreCase)
                ? new(RemoteTechnique.PsRemoting, "WinRM client (explicit credentials)", true)
            // cifs/ = SMB (file / admin shares, lateral tool transfer); RPCSS/ = DCOM / WMI endpoint mapper.
            : spn.StartsWith("cifs/", StringComparison.OrdinalIgnoreCase)
                ? new(RemoteTechnique.Smb, "SMB client (explicit credentials)", true)
            : spn.StartsWith("RPCSS/", StringComparison.OrdinalIgnoreCase)
                ? new(RemoteTechnique.Wmi, "WMI / DCOM client (explicit credentials)", true)
            : null;
        NormalizerBase.Apply(e, m);
    }

    private static void ProcessCreated(NormalizedEvent e, EventXmlData ev)
    {
        // Win10+ fills Target* when the new process runs as a different account; otherwise "-".
        var targetUser = ev.Get("TargetUserName");
        e.TargetUserName = targetUser ?? e.SubjectUserName;
        e.TargetDomain = targetUser is not null ? ev.Get("TargetDomainName") : e.SubjectDomain;
        e.Sid = targetUser is not null ? ev.Get("TargetUserSid") : ev.Get("SubjectUserSid");
        e.LogonId = NonZeroLogonId(ev.Get("TargetLogonId")) ?? e.SubjectLogonId;
        e.ProcessName = ev.Get("NewProcessName");
        e.ProcessId = ev.Get("NewProcessId");
        e.ParentProcessName = ev.Get("ParentProcessName");
        e.CommandLine = ev.Get("CommandLine");
        e.ElevatedToken = ev.Get("TokenElevationType") switch
        {
            "%%1937" => true,
            "%%1936" or "%%1938" => false,
            _ => null,
        };

        var m = RemoteExecPatterns.ClassifyProcess(e.ProcessName, e.ParentProcessName, e.CommandLine);
        if (m is not null) NormalizerBase.Apply(e, m);
        else e.KeepOnlyIfLinked = true;
        e.Details = e.CommandLine is null ? null : NormalizerBase.Truncate(e.CommandLine, 400);
    }

    private static void GroupMember(NormalizedEvent e, EventXmlData ev)
    {
        e.GroupName = ev.Get("TargetUserName");
        var memberDn = ev.Get("MemberName");
        var memberSid = ev.Get("MemberSid");
        var cn = memberDn is null ? null : CommonName.Match(memberDn);
        e.TargetUserName = cn is { Success: true } ? cn.Groups["cn"].Value.Replace("\\,", ",") : memberSid;
        e.Sid = memberSid;
        e.TargetDomain = ev.Get("TargetDomainName");
        e.Details = NormalizerBase.Join(
            $"Group: {e.TargetDomain}\\{e.GroupName}",
            memberDn is null ? null : $"Member: {memberDn}",
            e.SubjectUserName is null ? null : $"By {e.SubjectDomain}\\{e.SubjectUserName}");
    }

    private static void Kerberos(NormalizedEvent e, EventXmlData ev)
    {
        SetUser(e, ev.Get("TargetUserName"), ev.Get("TargetDomainName"));
        e.Sid = ev.Get("TargetSid");
        e.AuthenticationPackage = "Kerberos";
        e.ServiceName = ev.Get("ServiceName");
        e.Status = ev.GetAny("Status", "FailureCode");
        e.TicketEncryptionType = ev.Get("TicketEncryptionType");
        if (ev.EventId == 4769) e.TargetServer = e.ServiceName;

        if (ev.EventId == 4771 || !FailureReasonCatalog.IsZero(e.Status))
        {
            e.IsFailure = true;
            e.FailureReason = FailureReasonCatalog.DescribeKerberos(e.Status) ?? "Kerberos failure";
        }
        else
        {
            e.IsSuccess = true;
        }
        e.Details = NormalizerBase.Join(
            e.ServiceName is null ? null : $"Service: {e.ServiceName}",
            e.TicketEncryptionType is null ? null : $"Encryption: {e.TicketEncryptionType}");
    }

    /// <summary>Returns false when the share access is routine and should not produce a row.</summary>
    private static bool ShareAccess(NormalizedEvent e, EventXmlData ev)
    {
        ActorIsUser(e, ev);
        e.ShareName = ev.Get("ShareName");
        e.RelativeTargetName = ev.Get("RelativeTargetName");
        e.AccessMask = ev.Get("AccessMask");
        e.Details = NormalizerBase.Join(e.ShareName, e.RelativeTargetName, Collapse(ev.Get("AccessList")));

        if (ev.EventId == 5140)
        {
            if (!RemoteExecPatterns.IsAdminShare(e.ShareName)) return false;
            NormalizerBase.Apply(e, new RemoteExecMatch(RemoteTechnique.AdminShare, "Admin share mounted"));
            return true;
        }

        // 5145 is an access CHECK - which rights were requested and whether they were granted - not
        // proof that a file was copied. An executable / PSEXESVC "drop" needs requested write rights;
        // Impacket output files count on read (the attacker reads the command output back).
        RemoteExecMatch? m = null;
        if (RemoteExecPatterns.IsIpcShare(e.ShareName))
            m = RemoteExecPatterns.ClassifyPipe(e.RelativeTargetName);
        else if (RemoteExecPatterns.IsAdminShare(e.ShareName))
        {
            m = RemoteExecPatterns.ClassifyAdminShareFile(e.RelativeTargetName);
            if (m is { Technique: RemoteTechnique.AdminShare or RemoteTechnique.PsExec } &&
                !RequestsWrite(e.AccessMask, ev.Get("AccessList")))
                m = null;
        }
        if (m is null) return false;
        if (ev.IsAuditFailure)
        {
            // Denied: kept as context for the attempt, but no technique - nothing was opened.
            e.EventType = "Network share object access denied";
            e.Details = NormalizerBase.Join(e.Details, $"access DENIED ({m.Value.Variant ?? m.Value.Technique})");
            return true;
        }
        NormalizerBase.Apply(e, m);
        return true;
    }

    /// <summary>
    /// True when a share access requested write rights: WriteData / AddFile (0x2), AppendData (0x4),
    /// GENERIC_WRITE, GENERIC_ALL or MAXIMUM_ALLOWED, or %%4417 / %%4418 in the access list. When
    /// neither field is present the request is unknown and treated as a write (as before).
    /// </summary>
    internal static bool RequestsWrite(string? accessMask, string? accessList)
    {
        var m = accessMask?.Trim();
        if (m is not null && m.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            uint.TryParse(m[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var mask))
            return (mask & (0x2u | 0x4u | 0x40000000u | 0x10000000u | 0x02000000u)) != 0;
        if (!string.IsNullOrWhiteSpace(accessList))
            return accessList.Contains("%%4417", StringComparison.Ordinal) || accessList.Contains("%%4418", StringComparison.Ordinal);
        return true;
    }

    private static void ApplyServiceClassification(NormalizedEvent e)
    {
        var m = RemoteExecPatterns.ClassifyService(e.ServiceName, e.ServiceFileName);
        // Plain service installs carry no technique; the session builder upgrades them when they
        // are tied to a network logon.
        if (m is not null && (m.Value.Technique != RemoteTechnique.ServiceInstall || m.Value.Variant is not null))
            NormalizerBase.Apply(e, m);
    }

    /// <summary>For events whose subject IS the user of interest (service / task creator, share user).</summary>
    private static void ActorIsUser(NormalizedEvent e, EventXmlData ev)
    {
        e.TargetUserName = e.SubjectUserName;
        e.TargetDomain = e.SubjectDomain;
        e.Sid = ev.Get("SubjectUserSid");
        e.LogonId = e.SubjectLogonId;
    }

    private static void SetTarget(NormalizedEvent e, EventXmlData ev)
    {
        e.TargetUserName = ev.Get("TargetUserName") ?? e.SubjectUserName;
        e.TargetDomain = ev.Get("TargetDomainName") ?? e.SubjectDomain;
        e.Sid = ev.GetAny("TargetUserSid", "TargetSid", "SubjectUserSid");
    }

    private static void SetUser(NormalizedEvent e, string? user, string? domain = null)
    {
        var (u, d) = UserKey.Split(user);
        e.TargetUserName = u;
        e.TargetDomain = domain ?? d;
    }

    private static bool? ParseYesNo(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return value.Trim() switch
        {
            "%%1842" => true,
            "%%1843" => false,
            var v when v.Equals("yes", StringComparison.OrdinalIgnoreCase) => true,
            var v when v.Equals("no", StringComparison.OrdinalIgnoreCase) => false,
            _ => null,
        };
    }

    private static string? Impersonation(string? value) => value?.Trim() switch
    {
        null => null,
        "%%1832" => "Identification",
        "%%1833" => "Impersonation",
        "%%1840" => "Delegation",
        "%%1841" => "Denied by process trust label ACE",
        var v => v,
    };

    private static string? NonZeroLogonId(string? id) =>
        id is null || id is "0x0" or "0" ? null : id.ToLowerInvariant();

    private static string? NonZeroPort(string? port) => port is null or "0" ? null : port;

    private static string? Collapse(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : Whitespace.Replace(s.Trim(), " ");
}
