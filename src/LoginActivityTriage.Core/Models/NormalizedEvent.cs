namespace LoginActivityTriage.Core.Models;

/// <summary>
/// A single Windows authentication-related event after it has been parsed and
/// normalised into a flat, investigator-friendly shape. Fields are deliberately
/// nullable because different Event IDs populate different subsets of data and
/// real-world EVTX records are frequently missing fields.
/// </summary>
public sealed class NormalizedEvent
{
    /// <summary>Row id assigned by the storage layer (0 until persisted).</summary>
    public long Id { get; set; }

    /// <summary>Case this event belongs to.</summary>
    public long CaseId { get; set; }

    public DateTimeOffset Timestamp { get; set; }

    /// <summary>Computer the event was recorded on (from event XML or file path).</summary>
    public string? Hostname { get; set; }

    /// <summary>Friendly log source, e.g. "Security", "TerminalServices-LSM".</summary>
    public string? LogSource { get; set; }

    public int EventId { get; set; }

    public string? Provider { get; set; }

    public long? RecordId { get; set; }

    public string? Channel { get; set; }

    /// <summary>Human friendly description of the Event ID, e.g. "Successful logon".</summary>
    public string EventType { get; set; } = string.Empty;

    public string? TargetUserName { get; set; }

    public string? TargetDomain { get; set; }

    public string? Sid { get; set; }

    public string? SourceIp { get; set; }

    public string? SourcePort { get; set; }

    public string? WorkstationName { get; set; }

    public int? LogonType { get; set; }

    public string? LogonTypeDescription { get; set; }

    public string? AuthenticationPackage { get; set; }

    public string? LogonProcess { get; set; }

    public bool? ElevatedToken { get; set; }

    public string? ImpersonationLevel { get; set; }

    public string? ProcessName { get; set; }

    public string? ProcessId { get; set; }

    public string? TargetServer { get; set; }

    public string? ServiceName { get; set; }

    public string? GroupName { get; set; }

    public string? Status { get; set; }

    public string? SubStatus { get; set; }

    public string? FailureReason { get; set; }

    /// <summary>True for events that represent a confirmed successful authentication.</summary>
    public bool IsSuccess { get; set; }

    /// <summary>True for events that represent a failed authentication.</summary>
    public bool IsFailure { get; set; }

    public string? RawXml { get; set; }

    /// <summary>
    /// Transient UI flag set when this event matches an investigator-supplied IOC
    /// (host / IP / user). Not persisted; recomputed whenever the IOC list changes.
    /// </summary>
    public bool IsIoc { get; set; }

    /// <summary>True when the target account looks like a machine account (ends with $).</summary>
    public bool IsMachineAccount =>
        !string.IsNullOrEmpty(TargetUserName) && TargetUserName.EndsWith('$');

    /// <summary>True for privileged indicators (4672, or 4624 with an elevated token).</summary>
    public bool IsPrivileged => EventId == 4672 || ElevatedToken == true;

    /// <summary>True for events that indicate Remote Desktop activity.</summary>
    public bool IsRdp =>
        LogonType == 10 ||
        EventId == 1149 ||
        EventId is 21 or 22 or 24 or 25 or 39 or 40;

    /// <summary>True when the source IP is empty, localhost or the placeholder "-".</summary>
    public bool IsLocalOrBlankSource =>
        string.IsNullOrWhiteSpace(SourceIp) ||
        SourceIp is "-" or "::1" or "127.0.0.1" or "0.0.0.0";
}
