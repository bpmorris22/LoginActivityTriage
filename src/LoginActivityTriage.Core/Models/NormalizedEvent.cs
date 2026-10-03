using LoginActivityTriage.Core.Mapping;

namespace LoginActivityTriage.Core.Models;

/// <summary>
/// A single Windows authentication / remote-access event after it has been parsed
/// and normalised into a flat, investigator-friendly shape. Fields are nullable
/// because different Event IDs populate different subsets of data and real-world
/// EVTX records are frequently missing fields.
///
/// Timestamps are always UTC (offset 0).
/// </summary>
public sealed class NormalizedEvent
{
    /// <summary>Row id assigned by the storage layer (0 until persisted).</summary>
    public long Id { get; set; }

    /// <summary>Case this event belongs to.</summary>
    public long CaseId { get; set; }

    /// <summary>Event time, UTC.</summary>
    public DateTimeOffset Timestamp { get; set; }

    /// <summary>Computer the event was recorded on (from event XML or file path).</summary>
    public string? Hostname { get; set; }

    /// <summary>Friendly log source, e.g. "Security", "TerminalServices-LSM".</summary>
    public string? LogSource { get; set; }

    /// <summary>Full path of the EVTX file (or live channel name) the record came from.</summary>
    public string? SourceFile { get; set; }

    public int EventId { get; set; }
    public string? Provider { get; set; }
    public long? RecordId { get; set; }
    public string? Channel { get; set; }

    /// <summary>Human friendly description of the event, e.g. "Successful logon".</summary>
    public string EventType { get; set; } = string.Empty;

    /// <summary>The account the event is about (logon target, new process owner, member added...).</summary>
    public string? TargetUserName { get; set; }
    public string? TargetDomain { get; set; }
    public string? Sid { get; set; }

    /// <summary>The account that performed the action (4648 actor, 4697 installer, 4720 creator...).</summary>
    public string? SubjectUserName { get; set; }
    public string? SubjectDomain { get; set; }
    public string? SubjectLogonId { get; set; }

    /// <summary>Logon session id of the target session (4624 TargetLogonId, 4672/4688 session...).</summary>
    public string? LogonId { get; set; }
    public string? LinkedLogonId { get; set; }

    /// <summary>Terminal Services session id (LSM events).</summary>
    public string? SessionId { get; set; }

    public string? SourceIp { get; set; }
    public string? SourcePort { get; set; }
    public string? WorkstationName { get; set; }

    public int? LogonType { get; set; }
    public string? LogonTypeDescription { get; set; }
    public string? AuthenticationPackage { get; set; }
    public string? LogonProcess { get; set; }
    public bool? ElevatedToken { get; set; }
    public string? ImpersonationLevel { get; set; }
    public string? PrivilegeList { get; set; }

    public string? ProcessName { get; set; }
    public string? ProcessId { get; set; }
    public string? ParentProcessName { get; set; }
    public string? CommandLine { get; set; }

    /// <summary>Remote server named by the event (4648 TargetServerName, 4769 service, WinRM/RDP client target).</summary>
    public string? TargetServer { get; set; }

    public string? ServiceName { get; set; }
    public string? ServiceFileName { get; set; }
    public string? ServiceType { get; set; }
    public string? ServiceStartType { get; set; }
    public string? ServiceAccount { get; set; }

    public string? TaskName { get; set; }

    public string? ShareName { get; set; }
    public string? RelativeTargetName { get; set; }
    public string? AccessMask { get; set; }

    public string? GroupName { get; set; }
    public string? TicketEncryptionType { get; set; }

    public string? Status { get; set; }
    public string? SubStatus { get; set; }
    public string? FailureReason { get; set; }

    /// <summary>Short free-text summary of event-specific detail (resource URI, pipe, task command...).</summary>
    public string? Details { get; set; }

    /// <summary>Host's UTC offset in minutes, from System event 6013 (e.g. +480 for UTC+08:00).</summary>
    public int? UtcOffsetMinutes { get; set; }

    /// <summary>Remote-access technique this event is evidence of (see <see cref="RemoteTechnique"/>), or null.</summary>
    public string? Technique { get; set; }

    /// <summary>Tool / variant when recognisable, e.g. "Sysinternals PsExec", "Impacket smbexec".</summary>
    public string? TechniqueDetail { get; set; }

    /// <summary>Session / power meaning of the event (see <see cref="EventActivity"/>): logon, logoff, boot, shutdown...</summary>
    public string? Activity { get; set; }

    /// <summary>True when this host is the SOURCE of the remote activity (psexec.exe, mstsc, WinRM client).</summary>
    public bool IsOutbound { get; set; }

    /// <summary>True for events that represent a confirmed successful authentication / session start.</summary>
    public bool IsSuccess { get; set; }

    /// <summary>True for events that represent a failed authentication.</summary>
    public bool IsFailure { get; set; }

    public string? RawXml { get; set; }

    // ---- Transient (not persisted) ----

    /// <summary>Set when this event matches an investigator-supplied IOC. Recomputed on IOC change.</summary>
    public bool IsIoc { get; set; }

    /// <summary>
    /// Process-creation events (4688 / Sysmon 1) that do not match a remote-execution pattern are
    /// only kept when their logon session belongs to a remote logon. The importer marks them with
    /// this flag; <c>ProcessEventFilter</c> resolves it once the whole import is known.
    /// </summary>
    public bool KeepOnlyIfLinked { get; set; }

    /// <summary>Remote session this event was stitched into (assigned by the session builder).</summary>
    public int? RemoteSessionRef { get; set; }

    // ---- Derived ----

    /// <summary>True when the target account looks like a machine account (ends with $).</summary>
    public bool IsMachineAccount =>
        !string.IsNullOrEmpty(TargetUserName) && TargetUserName.EndsWith('$');

    /// <summary>True for SYSTEM, LOCAL/NETWORK SERVICE, DWM/UMFD, anonymous and machine accounts.</summary>
    public bool IsNoiseAccount => AccountClassifier.IsNoise(TargetUserName, Sid);

    /// <summary>
    /// Privileged indicator: a special-privilege assignment (4672) or an elevated token on a logon,
    /// for a real (non-system, non-machine) account.
    /// </summary>
    public bool IsPrivileged =>
        (EventId == 4672 || (ElevatedToken == true && EventId == 4624)) && !IsNoiseAccount;

    /// <summary>True for events that indicate Remote Desktop activity (inbound or outbound).</summary>
    public bool IsRdp => LogonType == 10 || Technique == RemoteTechnique.Rdp;

    /// <summary>True for inbound RDP evidence on this host (excludes this host's own RDP client use).</summary>
    public bool IsInboundRdp => IsRdp && !IsOutbound;

    /// <summary>
    /// One successful authentication, for counting: a 4624 (the limited half of an elevated
    /// split-token pair is skipped so one admin logon counts once) or a domain controller's
    /// successful TGT / NTLM validation. 4672, session-manager and ticket-renewal events describe
    /// the same logon again and are not counted.
    /// </summary>
    public bool CountsAsLogonSuccess =>
        (EventId == 4624 && !(LinkedLogonId is not null && ElevatedToken == false)) ||
        (EventId is 4768 or 4776 && IsSuccess);

    /// <summary>True when the source IP is empty, localhost or a placeholder.</summary>
    public bool IsLocalOrBlankSource => IpUtil.IsLocalOrBlank(SourceIp);

    /// <summary>Stable identity used to drop duplicate records (same EVTX copied twice, re-import...).</summary>
    public string DedupeKey =>
        RecordId is not null
            ? $"{HostKey.Of(Hostname)}|{Channel}|{EventId}|{RecordId}|{Timestamp.UtcTicks}"
            : $"{HostKey.Of(Hostname)}|{Channel}|{EventId}|{Timestamp.UtcTicks}|{TargetUserName}|{SourceIp}|{LogonId}";
}
