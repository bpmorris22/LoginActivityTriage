using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Parsing;
using Xunit;
using static LoginActivityTriage.Tests.EventXml;

namespace LoginActivityTriage.Tests;

/// <summary>
/// End-to-end detection tests: event XML → normalisers → session builder → findings, for
/// PsExec, PowerShell Remoting, WMI, RDP and outbound activity.
/// </summary>
public class RemoteExecutionTests
{
    private readonly EventNormalizer _n = new();
    private static readonly NormalizationContext Ctx = new();

    private List<NormalizedEvent> Normalize(params string[] xml)
    {
        var events = xml.Select(x => _n.Normalize(x, Ctx)).Where(e => e is not null).Select(e => e!).ToList();
        return ProcessEventFilter.Apply(events);
    }

    private static AnalysisResult Analyze(List<NormalizedEvent> events) => new SuspiciousSequenceAnalyzer().Run(events);

    // ------------------------------------------------------------------ PsExec

    [Fact]
    public void SysinternalsPsExec_IsStitchedIntoOneHighConfidenceSession()
    {
        var events = Normalize(
            Logon(T0, "SRV01.contoso.local", "admin", "CONTOSO", 3, "10.0.0.5", "0x5a1b2c", workstation: "WKS07"),
            Share(5145, T0.AddSeconds(1), "SRV01.contoso.local", "admin", "10.0.0.5", "\\\\*\\ADMIN$", "PSEXESVC.exe", "0x5a1b2c"),
            Share(5145, T0.AddSeconds(1), "SRV01.contoso.local", "admin", "10.0.0.5", "\\\\*\\IPC$", "svcctl", "0x5a1b2c"),
            ServiceInstall(T0.AddSeconds(2), "SRV01.contoso.local", "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"),
            Share(5145, T0.AddSeconds(3), "SRV01.contoso.local", "admin", "10.0.0.5", "\\\\*\\IPC$", "PSEXESVC-WKS07-4412-stdin", "0x5a1b2c"),
            Process(T0.AddSeconds(4), "SRV01.contoso.local", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\PSEXESVC.exe", "\"cmd\" /c whoami /all"),
            Logoff(T0.AddSeconds(90), "SRV01.contoso.local", "admin", "0x5a1b2c"));

        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal(RemoteTechnique.PsExec, s.Technique);
        Assert.Equal("Sysinternals PsExec", s.Variant);
        Assert.Equal("admin", s.User);
        Assert.Equal("10.0.0.5", s.SourceIp);
        Assert.Equal("WKS07", s.SourceHost);
        Assert.Equal("High", s.Confidence);
        Assert.Contains("whoami", s.Commands);
        Assert.Equal(T0.AddSeconds(90), s.End);
        Assert.All(events, e => Assert.Equal(s.Id, e.RemoteSessionRef));
        Assert.Contains(result.Findings, f => f.RuleName == "PsExec-style remote service execution" &&
                                               f.Severity == FindingSeverity.High && f.SessionRef == s.Id);
    }

    [Theory]
    [InlineData("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe", "Sysinternals PsExec")]
    [InlineData("PAExec-4412-WKS07", "%SystemRoot%\\PAExec-4412-WKS07.exe", "PAExec")]
    [InlineData("RemComSvc", "%SystemRoot%\\RemComSvc.exe", "RemCom")]
    [InlineData("BFRn", "%systemroot%\\kXtqPzLm.exe", "Impacket psexec")]
    [InlineData("BTOBTO", "%COMSPEC% /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > %TEMP%\\execute.bat", "Impacket smbexec")]
    [InlineData("a1b2c3d", "\\\\10.0.0.5\\ADMIN$\\a1b2c3d.exe", "Service binary on admin share (psexec-style)")]
    public void ServiceInstall_PsExecFamily_IsRecognised(string name, string image, string variant)
    {
        var e = _n.Normalize(ServiceInstall(T0, "SRV01", name, image), Ctx);

        Assert.NotNull(e);
        Assert.Equal(RemoteTechnique.PsExec, e!.Technique);
        Assert.Equal(variant, e.TechniqueDetail);
        Assert.Equal("S-1-5-21-1-2-3-500", e.Sid);
    }

    [Fact]
    public void BenignServiceInstall_CarriesNoTechnique()
    {
        var e = _n.Normalize(ServiceInstall(T0, "SRV01", "GoogleUpdater", "\"C:\\Program Files\\Google\\Update\\updater.exe\" --system --windows-service"), Ctx);
        Assert.NotNull(e);
        Assert.Null(e!.Technique);
    }

    [Fact]
    public void PowerShellEncodedServiceImagePath_IsSuspicious()
    {
        var e = _n.Normalize(ServiceInstall(T0, "SRV01", "x7Yw", "%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc SQBFAFgA"), Ctx);
        Assert.Equal(RemoteTechnique.ServiceInstall, e!.Technique);
        Assert.Equal("Service with command-line ImagePath", e.TechniqueDetail);
    }

    [Fact]
    public void RoutineShareAccess_IsNotImported()
    {
        var e = _n.Normalize(Share(5145, T0, "FS01", "jdoe", "10.0.0.8", "\\\\*\\Finance", "Q3\\budget.xlsx", "0x1"), Ctx);
        var pipe = _n.Normalize(Share(5145, T0, "FS01", "jdoe", "10.0.0.8", "\\\\*\\IPC$", "srvsvc", "0x1"), Ctx);
        Assert.Null(e);
        Assert.Null(pipe);
    }

    // ------------------------------------------------------------------ PowerShell Remoting

    [Fact]
    public void PowerShellRemoting_IsStitchedWithSourceIpFromNetworkLogon()
    {
        const string host = "SRV02.contoso.local";
        const string engine = "\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\tSequenceNumber=13\r\n\tHostName=ServerRemoteHost\r\n\tHostVersion=1.0.0.0\r\n\tHostApplication=C:\\Windows\\system32\\wsmprovhost.exe -Embedding\r\n\tEngineVersion=5.1.19041.1";
        var events = Normalize(
            Logon(T0, host, "jdoe", "CONTOSO", 3, "10.0.0.7", "0x77aa", auth: "Kerberos", logonProcess: "Kerberos"),
            Event(WinRm, "Microsoft-Windows-WinRM/Operational", 169, T0.AddSeconds(1), host,
                new[] { ("username", "CONTOSO\\jdoe"), ("authenticationMechanism", "Kerberos") }),
            Event(WinRm, "Microsoft-Windows-WinRM/Operational", 91, T0.AddSeconds(1), host,
                new[] { ("resourceUri", "http://schemas.microsoft.com/powershell/Microsoft.PowerShell") }, "S-1-5-21-1-2-3-1105"),
            Positional(PsClassic, "Windows PowerShell", 400, T0.AddSeconds(2), host, "Available", "None", engine),
            Event(PsOperational, "Microsoft-Windows-PowerShell/Operational", 4103, T0.AddSeconds(5), host, new[]
            {
                ("ContextInfo", "        Severity = Informational\r\n        Host Name = ServerRemoteHost\r\n        Host Application = C:\\Windows\\system32\\wsmprovhost.exe -Embedding\r\n        Command Name = Get-Process\r\n        User = CONTOSO\\jdoe\r\n        Connected User = \r\n"),
                ("UserData", ""), ("Payload", "CommandInvocation(Get-Process): \"Get-Process\""),
            }),
            Positional(PsClassic, "Windows PowerShell", 403, T0.AddMinutes(4), host, "Stopped", "Available", engine.Replace("Available", "Stopped")));

        Assert.Equal(6, events.Count);
        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal(RemoteTechnique.PsRemoting, s.Technique);
        Assert.Equal("jdoe", s.User);
        Assert.Equal("10.0.0.7", s.SourceIp);
        Assert.Equal("Kerberos", s.AuthPackage);
        Assert.Contains("Get-Process", s.Commands);
        Assert.Contains(result.Findings, f => f.RuleName == "PowerShell Remoting session");
    }

    [Fact]
    public void LocalPowerShell_IsIgnored()
    {
        var e = _n.Normalize(Positional(PsClassic, "Windows PowerShell", 400, T0, "WKS01", "Available", "None",
            "\tHostName=ConsoleHost\r\n\tHostApplication=powershell.exe"), Ctx);
        Assert.Null(e);
    }

    [Fact]
    public void WinRmClientSession_IsOutboundWithTarget()
    {
        var e = _n.Normalize(Event(WinRm, "Microsoft-Windows-WinRM/Operational", 6, T0, "WKS01.contoso.local",
            new[] { ("connection", "srv02.contoso.local/wsman?PSVersion=5.1.19041.1") }), Ctx);
        Assert.NotNull(e);
        Assert.True(e!.IsOutbound);
        Assert.Equal(RemoteTechnique.PsRemoting, e.Technique);
        Assert.Equal("srv02.contoso.local", e.TargetServer);
    }

    // ------------------------------------------------------------------ WMI / DCOM / tasks

    [Fact]
    public void ImpacketWmiexec_IsDetectedAndLinkedToLogon()
    {
        var events = Normalize(
            Logon(T0, "SRV03", "admin", "CONTOSO", 3, "10.0.0.66", "0x9911"),
            Process(T0.AddSeconds(2), "SRV03", "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
                "cmd.exe /Q /c whoami 1> \\\\127.0.0.1\\ADMIN$\\__1718877600.123 2>&1", "admin", "0x9911"));

        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal(RemoteTechnique.Wmi, s.Technique);
        Assert.Equal("Impacket wmiexec", s.Variant);
        Assert.Equal("10.0.0.66", s.SourceIp);
        Assert.Contains(result.Findings, f => f.RuleName == "Remote WMI execution" && f.Severity == FindingSeverity.High);
    }

    [Fact]
    public void ScheduledTaskFromNetworkLogon_IsRemoteTask()
    {
        var task = "&lt;?xml version=\"1.0\"?&gt;&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;&lt;Command&gt;cmd.exe&lt;/Command&gt;&lt;Arguments&gt;/C whoami &gt; %windir%\\Temp\\aBcDeFgH.tmp 2&gt;&amp;1&lt;/Arguments&gt;&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;";
        var events = Normalize(
            Logon(T0, "SRV04", "admin", "CONTOSO", 3, "10.0.0.66", "0x4242"),
            Sec(4698, T0.AddSeconds(1), "SRV04", ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "admin"),
                ("SubjectDomainName", "CONTOSO"), ("SubjectLogonId", "0x4242"), ("TaskName", "\\XyZaBcDe"),
                ("TaskContent", System.Net.WebUtility.HtmlDecode(task))));

        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal(RemoteTechnique.ScheduledTask, s.Technique);
        Assert.Equal("Impacket atexec", s.Variant);
        Assert.Contains("whoami", s.Commands);
    }

    // ------------------------------------------------------------------ RDP

    [Fact]
    public void RdpSession_LifecycleIsStitched_AndExternalSourceFlagged()
    {
        const string host = "TS01.contoso.local";
        var events = Normalize(
            UserData(Rcm, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149, T0, host, "EventXML",
                new[] { ("Param1", "jdoe"), ("Param2", "CONTOSO"), ("Param3", "198.51.100.23") }),
            Logon(T0.AddSeconds(2), host, "jdoe", "CONTOSO", 10, "198.51.100.23", "0x1f00a", auth: "Negotiate",
                workstation: "HOMEPC", elevated: "%%1842", logonProcess: "User32"),
            EventXml.Lsm(21, T0.AddSeconds(3), host, "CONTOSO\\jdoe", "3", "198.51.100.23"),
            EventXml.Lsm(22, T0.AddSeconds(4), host, "CONTOSO\\jdoe", "3", "198.51.100.23"),
            EventXml.Lsm(24, T0.AddMinutes(30), host, "CONTOSO\\jdoe", "3", "198.51.100.23"),
            EventXml.Lsm(25, T0.AddMinutes(90), host, "CONTOSO\\jdoe", "3", "198.51.100.99"),
            EventXml.Lsm(23, T0.AddMinutes(120), host, "CONTOSO\\jdoe", "3", null));

        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal(RemoteTechnique.Rdp, s.Technique);
        Assert.Equal("jdoe", s.User);
        Assert.Contains("198.51.100.23", s.SourceIp);
        Assert.Contains("198.51.100.99", s.SourceIp); // reconnected from a different address
        Assert.Equal(T0.AddMinutes(120), s.End);
        Assert.Equal("High", s.Confidence);
        Assert.Contains(result.Findings, f => f.RuleName == "RDP logon from external address");
    }

    [Fact]
    public void Rdp1149_IsNotASuccessfulLogon()
    {
        var e = _n.Normalize(UserData(Rcm, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", 1149, T0, "TS01",
            "EventXML", new[] { ("Param1", "jdoe"), ("Param2", "CONTOSO"), ("Param3", "10.1.1.1") }), Ctx);
        Assert.NotNull(e);
        Assert.False(e!.IsSuccess);
        Assert.True(e.IsRdp);
        Assert.Equal("10.1.1.1", e.SourceIp);
    }

    [Fact]
    public void ConsoleLogon_IsNotRdp()
    {
        var e = _n.Normalize(EventXml.Lsm(21, T0, "WKS01", "CONTOSO\\jdoe", "1", "LOCAL"), Ctx);
        Assert.NotNull(e);
        Assert.False(e!.IsRdp);
        Assert.Equal("jdoe", e.TargetUserName);
        Assert.Equal("CONTOSO", e.TargetDomain);
    }

    [Theory]
    [InlineData("LOCAL")]
    [InlineData("本機")]
    [InlineData("LOKAL")]
    public void LocalisedConsoleAddress_IsNotRdp(string address)
    {
        var e = _n.Normalize(EventXml.Lsm(21, T0, "WKS01", "CONTOSO\\jdoe", "1", address), Ctx);
        Assert.NotNull(e);
        Assert.False(e!.IsRdp);
        Assert.Null(e.SourceIp);
    }

    [Fact]
    public void KernelBoot25InSystemLog_IsNotAnRdpReconnect()
    {
        var xml = Event("Microsoft-Windows-Kernel-Boot", "System", 25, T0, "WKS01",
            new[] { ("BootMenuPolicy", "1") });
        Assert.Null(_n.Normalize(xml, Ctx));
    }

    [Fact]
    public void RdpCoreTs131_SplitsAddressAndPort()
    {
        var e = _n.Normalize(Event(CoreTs, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", 131, T0, "TS01",
            new[] { ("ConnType", "TCP"), ("ClientIP", "203.0.113.9:53122") }), Ctx);
        Assert.Equal("203.0.113.9", e!.SourceIp);
        Assert.Equal("53122", e.SourcePort);
        Assert.True(e.IsRdp);
    }

    // ------------------------------------------------------------------ outbound

    [Fact]
    public void PsExecClient_OnSourceHost_IsOutboundSession()
    {
        var events = Normalize(
            Process(T0, "WKS07", "C:\\Tools\\PsExec64.exe", "C:\\Windows\\System32\\cmd.exe",
                "PsExec64.exe \\\\SRV01 -s cmd.exe", "admin", "0x3e1"));

        var result = Analyze(events);

        var s = Assert.Single(result.Sessions);
        Assert.Equal("Outbound", s.Direction);
        Assert.Equal(RemoteTechnique.PsExec, s.Technique);
        Assert.Equal("SRV01", s.TargetHost);
        Assert.Contains(result.Findings, f => f.RuleName == "Outbound PsExec from this host");
    }

    [Fact]
    public void ExplicitCredentialsToHttpSpn_IsOutboundWinRm()
    {
        var e = _n.Normalize(Sec(4648, T0, "WKS07", ("SubjectUserName", "jdoe"), ("SubjectDomainName", "CONTOSO"),
            ("SubjectLogonId", "0x3e1"), ("TargetUserName", "adm_jdoe"), ("TargetDomainName", "CONTOSO"),
            ("TargetServerName", "srv02.contoso.local"), ("TargetInfo", "HTTP/srv02.contoso.local"),
            ("ProcessName", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")), Ctx);
        Assert.True(e!.IsOutbound);
        Assert.Equal(RemoteTechnique.PsRemoting, e.Technique);
        Assert.Equal("jdoe", e.SubjectUserName);
        Assert.Equal("adm_jdoe", e.TargetUserName);
    }

    // ------------------------------------------------------------------ other rules

    [Fact]
    public void SecurityLogCleared_IsCritical()
    {
        var xml = UserData("Microsoft-Windows-Eventlog", "Security", 1102, T0, "SRV01", "LogFileCleared",
            new[] { ("SubjectUserSid", "S-1-5-21-1-2-3-500"), ("SubjectUserName", "admin"), ("SubjectDomainName", "CONTOSO"), ("SubjectLogonId", "0x123") });
        var events = Normalize(xml);
        Assert.Equal(RemoteTechnique.LogCleared, events[0].Technique);
        var findings = Analyze(events).Findings;
        Assert.Contains(findings, f => f.RuleName == "Event log cleared" && f.Severity == FindingSeverity.Critical);
    }

    [Fact]
    public void NewAccountAddedToDomainAdmins_IsCritical()
    {
        var events = Normalize(
            Sec(4720, T0, "DC01", ("TargetUserName", "svc_backup2"), ("TargetDomainName", "CONTOSO"), ("TargetSid", "S-1-5-21-1-2-3-4444"),
                ("SubjectUserName", "admin"), ("SubjectDomainName", "CONTOSO")),
            Sec(4728, T0.AddMinutes(2), "DC01", ("MemberName", "CN=svc_backup2,CN=Users,DC=contoso,DC=local"),
                ("MemberSid", "S-1-5-21-1-2-3-4444"), ("TargetUserName", "Domain Admins"), ("TargetDomainName", "CONTOSO"),
                ("SubjectUserName", "admin"), ("SubjectDomainName", "CONTOSO")));
        Assert.Equal("svc_backup2", events[1].TargetUserName);
        Assert.Equal("Domain Admins", events[1].GroupName);
        Assert.Contains(Analyze(events).Findings, f => f.RuleName == "New account added to privileged group" && f.Severity == FindingSeverity.Critical);
    }

    [Fact]
    public void LocalAccountNetworkLogonOverNtlm_IsFlagged()
    {
        var events = Normalize(Logon(T0, "SRV05", "Administrator", "SRV05", 3, "10.0.0.66", "0x5151"));
        Assert.Contains(Analyze(events).Findings, f => f.RuleName == "Local account used for remote logon");
    }

    [Fact]
    public void NewCredentialsSeclogo_IsFlagged()
    {
        var events = Normalize(Logon(T0, "WKS07", "jdoe", "CONTOSO", 9, "::1", "0x6161", auth: "Negotiate", logonProcess: "seclogo"));
        Assert.Contains(Analyze(events).Findings, f => f.RuleName.StartsWith("NewCredentials logon"));
    }

    [Fact]
    public void Kerberoasting_IsFlagged()
    {
        var xml = Enumerable.Range(0, 4).Select(i => Sec(4769, T0.AddSeconds(i), "DC01",
            ("TargetUserName", "jdoe@CONTOSO.LOCAL"), ("TargetDomainName", "CONTOSO.LOCAL"), ("ServiceName", $"svc_sql{i}"),
            ("TicketEncryptionType", "0x17"), ("IpAddress", "::ffff:10.0.0.66"), ("Status", "0x0"))).ToArray();
        var events = Normalize(xml);
        Assert.Equal("jdoe", events[0].TargetUserName);
        Assert.Equal("10.0.0.66", events[0].SourceIp);
        Assert.Contains(Analyze(events).Findings, f => f.RuleName.StartsWith("Possible Kerberoasting"));
    }
}
