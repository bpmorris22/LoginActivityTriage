using System.Text.RegularExpressions;

namespace LoginActivityTriage.Core.Mapping;

/// <summary>A recognised remote-execution pattern: technique, tool variant and direction.</summary>
public readonly record struct RemoteExecMatch(string Technique, string? Variant, bool Outbound = false);

/// <summary>
/// Pattern library for remote execution artifacts (defensive detection). Matches service installs,
/// named pipes, admin-share file names and process lineage left by PsExec and its clones, Impacket,
/// WMI, DCOM, WinRM / PowerShell Remoting and remote scheduled tasks.
///
/// Patterns are deliberately conservative and each returns a tool variant so analysts can judge
/// the match. Absence of a match is not absence of activity.
/// </summary>
public static class RemoteExecPatterns
{
    private const RegexOptions Opt = RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // ---------- Service installs (7045 / 4697) ----------

    private static readonly Regex ImpacketPsexecImage = new(@"^%systemroot%\\[a-z0-9]{8}\.exe$", Opt);
    private static readonly Regex RandomServiceName4 = new(@"^[a-z]{4}$", Opt);
    private static readonly Regex AdminShareImage = new(@"^\\\\[^\\]+\\(admin|[a-z])\$\\", Opt);
    private static readonly Regex CommandImage = new(@"(%comspec%|cmd(\.exe)?\s+/[cqrb]|powershell|pwsh|mshta|rundll32|regsvr32)", Opt);

    // ---------- Remote access / RMM software ----------

    /// <summary>(fragment matched in service name or binary path, tool name). Case-insensitive.</summary>
    private static readonly (string Fragment, string Tool)[] RemoteAccessTools =
    {
        ("SRsvcSOS", "Splashtop SOS (on-demand support)"), ("unpacksos", "Splashtop SOS (on-demand support)"),
        ("Splashtop", "Splashtop"), ("SRService", "Splashtop"), ("SRServer", "Splashtop"), ("SRManager", "Splashtop"),
        ("AnyDesk", "AnyDesk"),
        ("TeamViewer", "TeamViewer"),
        ("ScreenConnect", "ConnectWise ScreenConnect"), ("ConnectWiseControl", "ConnectWise ScreenConnect"),
        ("AteraAgent", "Atera"),
        ("RustDesk", "RustDesk"),
        ("NetSupport", "NetSupport Manager"), ("client32.exe", "NetSupport Manager"),
        ("LogMeIn", "LogMeIn"), ("LMIGuardian", "LogMeIn"), ("LMIRescue", "LogMeIn Rescue"),
        ("GoToAssist", "GoTo Resolve / GoToAssist"), ("GoTo Resolve", "GoTo Resolve / GoToAssist"), ("GoToResolve", "GoTo Resolve / GoToAssist"),
        ("Kaseya", "Kaseya VSA"), ("AgentMon.exe", "Kaseya VSA"),
        ("BASupportExpress", "N-able Take Control"), ("Take Control Agent", "N-able Take Control"),
        ("ZohoAssist", "Zoho Assist"), ("Zoho Assist", "Zoho Assist"), ("ZA_Connect", "Zoho Assist"),
        ("MeshAgent", "MeshCentral"),
        ("rutserv", "Remote Utilities"), ("Remote Utilities", "Remote Utilities"),
        ("DameWare", "DameWare"), ("dwrcs", "DameWare"),
        ("chromoting", "Chrome Remote Desktop"), ("Chrome Remote Desktop", "Chrome Remote Desktop"),
        ("tvnserver", "TightVNC"), ("TightVNC", "TightVNC"), ("UltraVNC", "UltraVNC"), ("uvnc_service", "UltraVNC"),
        ("winvnc", "VNC"), ("vncserver", "VNC"), ("RealVNC", "RealVNC"),
        ("Ammyy", "Ammyy Admin"), ("Supremo", "Supremo"), ("rserver3", "Radmin"), ("Radmin", "Radmin"),
        ("SimpleHelp", "SimpleHelp"), ("bomgar-scc", "BeyondTrust Remote Support"), ("BeyondTrust", "BeyondTrust Remote Support"),
        ("PCMonitorSrv", "Pulseway"), ("NinjaRMMAgent", "NinjaOne"), ("CagService", "Datto RMM"),
        ("Syncro", "Syncro"), ("tacticalrmm", "Tactical RMM"), ("Action1", "Action1"), ("Level.io", "Level"),
        ("QuickAssist", "Quick Assist"),
        // First match wins: HopToDesk before ToDesk ("HopToDesk.exe" contains "ToDesk.exe").
        ("HopToDesk", "HopToDesk"),
        ("ToDesk_Service", "ToDesk"), ("\\ToDesk\\", "ToDesk"), ("ToDesk.exe", "ToDesk"),
        ("Sunlogin", "Sunlogin (Oray)"), ("AweSun", "AweSun (AweRay)"),
        ("UltraViewer", "UltraViewer"), ("UltraViewService", "UltraViewer"),
        ("AnyViewer", "AnyViewer (AOMEI)"),
        ("ISLLight", "ISL Online"), ("ISL Online", "ISL Online"), ("ISL AlwaysOn", "ISL Online"),
        ("DWAgent", "DWService"),
        ("parsecd", "Parsec"), ("\\Parsec\\", "Parsec"),
        ("IperiusRemote", "Iperius Remote"),
        ("Getscreen", "Getscreen.me"),
        ("FleetDeck", "FleetDeck"),
        ("Remotely_Agent", "Remotely"),
        ("NoMachine", "NoMachine"), ("nxservice", "NoMachine"),
        ("GoToMyPC", "GoToMyPC"),
        ("LiteManager", "LiteManager"),
        ("TigerVNC", "TigerVNC"),
        ("pcAnywhere", "pcAnywhere"), ("awhost32", "pcAnywhere"),
        ("Mikogo", "Mikogo"), ("ShowMyPC", "ShowMyPC"),
        ("Jump Desktop", "Jump Desktop"), ("\\RemotePC\\", "RemotePC"),
        ("Bomgar", "BeyondTrust Remote Support"),
        ("\\Netop\\", "Netop Remote Control"), ("nhstw32", "Netop Remote Control"),
        ("SuperOps", "SuperOps"),
    };

    private static readonly Regex UserWritablePath = new(@"\\(temp|tmp|appdata|downloads|users\\public|programdata\\[^\\]+\\temp)\\", Opt);

    /// <summary>Recognises third-party remote access / RMM software by service name or binary path.</summary>
    public static RemoteExecMatch? ClassifyRemoteAccessTool(string? serviceName, string? path)
    {
        var text = $"{serviceName} {path}";
        if (string.IsNullOrWhiteSpace(text)) return null;
        foreach (var (fragment, tool) in RemoteAccessTools)
            if (text.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return new(RemoteTechnique.RemoteAccessTool, tool);
        return null;
    }

    /// <summary>True when a binary runs from a temp / user-writable folder (portable or on-demand installs).</summary>
    public static bool IsUserWritablePath(string? path) =>
        !string.IsNullOrWhiteSpace(path) && UserWritablePath.IsMatch(path);

    /// <summary>Classifies a service install by name and image path.</summary>
    public static RemoteExecMatch? ClassifyService(string? serviceName, string? imagePath)
    {
        var name = serviceName?.Trim() ?? string.Empty;
        var img = imagePath?.Trim().Trim('"') ?? string.Empty;
        if (name.Length == 0 && img.Length == 0) return null;

        if (name.Equals("PSEXESVC", StringComparison.OrdinalIgnoreCase) ||
            img.EndsWith("\\PSEXESVC.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Sysinternals PsExec");
        if (name.StartsWith("PAExec", StringComparison.OrdinalIgnoreCase) ||
            img.Contains("\\PAExec", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "PAExec");
        if (name.StartsWith("RemCom", StringComparison.OrdinalIgnoreCase) ||
            img.Contains("RemComSvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "RemCom");
        if (name.Equals("csexecsvc", StringComparison.OrdinalIgnoreCase) ||
            img.Contains("csexecsvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "CSExec");
        if (name.Equals("winexesvc", StringComparison.OrdinalIgnoreCase) ||
            img.Contains("winexesvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "winexe");
        if (img.Contains("__output", StringComparison.OrdinalIgnoreCase) &&
            img.Contains("echo", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Impacket smbexec");
        if (name.Equals("BTOBTO", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Impacket smbexec");
        if (ImpacketPsexecImage.IsMatch(img))
            return new(RemoteTechnique.PsExec,
                RandomServiceName4.IsMatch(name) ? "Impacket psexec" : "Random-named service binary (psexec-style)");
        if (AdminShareImage.IsMatch(img))
            return new(RemoteTechnique.PsExec, "Service binary on admin share (psexec-style)");
        if (ClassifyRemoteAccessTool(name, img) is { } rat)
            return rat;
        if (CommandImage.IsMatch(img))
            return new(RemoteTechnique.ServiceInstall, "Service with command-line ImagePath");
        return new(RemoteTechnique.ServiceInstall, null);
    }

    /// <summary>True when a service name belongs to a known remote-exec tool (for 7036 state changes).</summary>
    public static bool IsKnownRemoteExecServiceName(string? name) =>
        !string.IsNullOrWhiteSpace(name) &&
        (name.Equals("PSEXESVC", StringComparison.OrdinalIgnoreCase) ||
         name.StartsWith("PAExec", StringComparison.OrdinalIgnoreCase) ||
         name.StartsWith("RemCom", StringComparison.OrdinalIgnoreCase) ||
         name.Equals("csexecsvc", StringComparison.OrdinalIgnoreCase) ||
         name.Equals("winexesvc", StringComparison.OrdinalIgnoreCase) ||
         name.Equals("BTOBTO", StringComparison.OrdinalIgnoreCase));

    // ---------- Named pipes (5145 on IPC$, Sysmon 17/18) ----------

    /// <summary>Classifies a named pipe used by remote execution tooling.</summary>
    public static RemoteExecMatch? ClassifyPipe(string? pipe)
    {
        if (string.IsNullOrWhiteSpace(pipe)) return null;
        var p = pipe.Trim().TrimStart('\\');
        if (p.StartsWith("pipe\\", StringComparison.OrdinalIgnoreCase)) p = p[5..];

        if (p.StartsWith("PSEXESVC", StringComparison.OrdinalIgnoreCase) ||
            p.StartsWith("psexecsvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Sysinternals PsExec");
        if (p.StartsWith("RemCom", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "RemCom / Impacket psexec");
        if (p.StartsWith("PAExec", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "PAExec");
        if (p.StartsWith("csexecsvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "CSExec");
        if (p.StartsWith("winexesvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "winexe");
        if (p.Equals("svcctl", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.RemoteServiceControl, "Remote SCM (svcctl)");
        if (p.Equals("atsvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.ScheduledTask, "Remote task scheduler (atsvc)");
        return null;
    }

    // ---------- Admin share file access (5140 / 5145) ----------

    private static readonly Regex ExecutableName = new(@"\.(exe|dll|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|msi|scr|sys|wsf|cpl)$", Opt);
    private static readonly Regex ImpacketOutputFile = new(@"(^|\\)__(output|\d{6,}(\.\d+)?)$", Opt);

    /// <summary>True for ADMIN$, C$, D$ ... (hidden admin shares), excluding IPC$.</summary>
    public static bool IsAdminShare(string? share)
    {
        if (string.IsNullOrWhiteSpace(share)) return false;
        var s = share.Trim();
        var leaf = s[(s.LastIndexOf('\\') + 1)..];
        return leaf.EndsWith('$') && !leaf.Equals("IPC$", StringComparison.OrdinalIgnoreCase) &&
               !leaf.Equals("print$", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsIpcShare(string? share) =>
        !string.IsNullOrWhiteSpace(share) && share.Trim().EndsWith("IPC$", StringComparison.OrdinalIgnoreCase);

    /// <summary>Classifies a file touched on an admin share (binary drop, Impacket output file).</summary>
    public static RemoteExecMatch? ClassifyAdminShareFile(string? relativeTarget)
    {
        if (string.IsNullOrWhiteSpace(relativeTarget)) return null;
        var t = relativeTarget.Trim();
        if (t.EndsWith("PSEXESVC.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Sysinternals PsExec");
        if (ImpacketOutputFile.IsMatch(t))
            return new(RemoteTechnique.Wmi, "Impacket wmiexec / dcomexec / smbexec output file");
        if (ExecutableName.IsMatch(t))
            return new(RemoteTechnique.AdminShare, "Executable / script on admin share");
        return null;
    }

    // ---------- Process lineage (4688 / Sysmon 1) ----------

    private static readonly Regex ImpacketRedirect = new(@"\\\\127\.0\.0\.1\\(admin|c)\$\\__", Opt);
    private static readonly Regex AtexecRedirect = new(@">\s*%?\\?windir%?\\temp\\[a-z0-9]{8}\.tmp\s+2>&1", Opt);
    private static readonly Regex ShellChild = new(@"\\(cmd|powershell|pwsh|rundll32|mshta|regsvr32|wscript|cscript|certutil|bitsadmin|msbuild)\.exe$", Opt);
    private static readonly Regex PsRemotingCmd = new(@"\b(Enter-PSSession|Invoke-Command|New-PSSession)\b[^|;]*-(ComputerName|Session|cn)\b", Opt);
    private static readonly Regex WmicNode = new(@"\bwmic(\.exe)?\b.*\s/node:", Opt);
    private static readonly Regex InvokeWmiRemote = new(@"\b(Invoke-WmiMethod|Invoke-CimMethod|New-CimSession)\b.*-(ComputerName|CimSession)\b", Opt);
    private static readonly Regex SchtasksRemote = new(@"\bschtasks(\.exe)?\b.*\s/s\s", Opt);
    private static readonly Regex ScRemote = new(@"\bsc(\.exe)?\s+\\\\", Opt);

    private static string Leaf(string? path) =>
        string.IsNullOrWhiteSpace(path) ? string.Empty : path.Trim().Trim('"')[(path.Trim().Trim('"').LastIndexOf('\\') + 1)..];

    /// <summary>
    /// Classifies a process creation by image, parent and command line. Returns null when the
    /// process is not itself evidence of remote execution.
    /// </summary>
    public static RemoteExecMatch? ClassifyProcess(string? image, string? parentImage, string? commandLine)
    {
        var img = Leaf(image);
        var parent = Leaf(parentImage);
        var cmd = commandLine ?? string.Empty;

        // ---- Inbound (this host is the target) ----
        if (img.Equals("PSEXESVC.exe", StringComparison.OrdinalIgnoreCase) ||
            parent.Equals("PSEXESVC.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Sysinternals PsExec");
        if (img.StartsWith("PAExec", StringComparison.OrdinalIgnoreCase) ||
            parent.StartsWith("PAExec", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "PAExec");
        if (img.StartsWith("RemComSvc", StringComparison.OrdinalIgnoreCase) ||
            parent.StartsWith("RemComSvc", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "RemCom");
        if (img.Equals("wsmprovhost.exe", StringComparison.OrdinalIgnoreCase) ||
            parent.Equals("wsmprovhost.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsRemoting, "WinRM plugin host (wsmprovhost)");
        if (parent.Equals("winrshost.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.WinRs, "WinRS shell (winrshost)");
        if (ImpacketRedirect.IsMatch(cmd))
        {
            if (parent.Equals("mmc.exe", StringComparison.OrdinalIgnoreCase) ||
                parent.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
                return new(RemoteTechnique.Dcom, "Impacket dcomexec");
            if (parent.Equals("services.exe", StringComparison.OrdinalIgnoreCase))
                return new(RemoteTechnique.PsExec, "Impacket smbexec");
            return new(RemoteTechnique.Wmi, "Impacket wmiexec");
        }
        if (parent.Equals("services.exe", StringComparison.OrdinalIgnoreCase) &&
            cmd.Contains("__output", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Impacket smbexec");
        if (parent.Equals("WmiPrvSE.exe", StringComparison.OrdinalIgnoreCase) && ShellChild.IsMatch(img.Insert(0, "\\")))
            return new(RemoteTechnique.Wmi, "Shell spawned by WmiPrvSE");
        if (parent.Equals("mmc.exe", StringComparison.OrdinalIgnoreCase) && ShellChild.IsMatch(img.Insert(0, "\\")) &&
            cmd.Contains("/Q /c", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.Dcom, "Shell spawned by MMC (MMC20.Application)");
        if (AtexecRedirect.IsMatch(cmd))
            return new(RemoteTechnique.ScheduledTask, "Impacket atexec");

        // ---- Remote access / RMM software started on this host ----
        if (img.Length > 0 && ClassifyRemoteAccessTool(null, image) is { } rat)
            return rat;

        // ---- Outbound (this host is the source) ----
        if (img.Equals("psexec.exe", StringComparison.OrdinalIgnoreCase) ||
            img.Equals("psexec64.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "Sysinternals PsExec (client)", true);
        if (img.Equals("paexec.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.PsExec, "PAExec (client)", true);
        if (img.Equals("mstsc.exe", StringComparison.OrdinalIgnoreCase) && cmd.Contains("/v", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.Rdp, "mstsc /v (client)", true);
        if (img.Equals("winrs.exe", StringComparison.OrdinalIgnoreCase))
            return new(RemoteTechnique.WinRs, "winrs.exe (client)", true);
        if (PsRemotingCmd.IsMatch(cmd))
            return new(RemoteTechnique.PsRemoting, "PowerShell remoting cmdlet (client)", true);
        if (WmicNode.IsMatch(cmd) || InvokeWmiRemote.IsMatch(cmd))
            return new(RemoteTechnique.Wmi, "Remote WMI call (client)", true);
        if (SchtasksRemote.IsMatch(cmd))
            return new(RemoteTechnique.ScheduledTask, "schtasks /s (client)", true);
        if (ScRemote.IsMatch(cmd))
            return new(RemoteTechnique.RemoteServiceControl, "sc.exe \\\\host (client)", true);
        return null;
    }

    // ---------- Scheduled tasks (4698) ----------

    /// <summary>Classifies a scheduled task by its action command line.</summary>
    public static RemoteExecMatch ClassifyTask(string? command)
    {
        if (!string.IsNullOrWhiteSpace(command) && AtexecRedirect.IsMatch(command))
            return new(RemoteTechnique.ScheduledTask, "Impacket atexec");
        return new(RemoteTechnique.ScheduledTask, null);
    }

    private static readonly Regex TaskCommand = new(@"<Command>(?<c>.*?)</Command>", Opt | RegexOptions.Singleline);
    private static readonly Regex TaskArgs = new(@"<Arguments>(?<a>.*?)</Arguments>", Opt | RegexOptions.Singleline);

    /// <summary>Extracts "Command Arguments" from a 4698 TaskContent XML blob (escaped or not).</summary>
    public static string? TaskCommandLine(string? taskContent)
    {
        if (string.IsNullOrWhiteSpace(taskContent)) return null;
        var xml = System.Net.WebUtility.HtmlDecode(taskContent);
        var c = TaskCommand.Match(xml);
        if (!c.Success) return null;
        var a = TaskArgs.Match(xml);
        var cmd = c.Groups["c"].Value.Trim();
        return a.Success ? $"{cmd} {a.Groups["a"].Value.Trim()}" : cmd;
    }
}
