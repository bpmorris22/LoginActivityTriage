namespace LoginActivityTriage.Core.Models;

/// <summary>
/// A stitched remote-access session: one RDP session, one PsExec run, one PowerShell Remoting
/// session, etc., assembled from several events on the same host by the session builder.
/// </summary>
public sealed class RemoteSession
{
    public int Id { get; set; }

    /// <summary>See <c>RemoteTechnique</c>.</summary>
    public string Technique { get; set; } = string.Empty;

    /// <summary>Tool / variant when recognisable.</summary>
    public string? Variant { get; set; }

    /// <summary>"Inbound" (this host was accessed) or "Outbound" (this host was the source).</summary>
    public string Direction { get; set; } = "Inbound";

    /// <summary>Host whose logs recorded the session.</summary>
    public string? Host { get; set; }

    /// <summary>For outbound sessions: the remote destination as logged (often an IP).</summary>
    public string? TargetHost { get; set; }

    /// <summary>For outbound sessions: the destination's name when another event resolves it (4648 target server).</summary>
    public string? TargetHostName { get; set; }

    /// <summary>For outbound sessions: credentials used for the connection when different from the user (4648).</summary>
    public string? CredentialsUsed { get; set; }

    /// <summary>UTC.</summary>
    public DateTimeOffset Start { get; set; }
    /// <summary>UTC.</summary>
    public DateTimeOffset End { get; set; }

    public string? User { get; set; }
    public string? Domain { get; set; }

    /// <summary>
    /// INFERENCE, not evidence: for an outbound session whose logs name no account, the only
    /// account that logged on interactively to <see cref="Host"/> anywhere in the evidence.
    /// <see cref="User"/> stays empty; <see cref="Evidence"/> states the basis.
    /// </summary>
    public string? InferredUser { get; set; }
    public string? SourceIp { get; set; }
    public string? SourceHost { get; set; }
    public string? LogonId { get; set; }
    public int? LogonType { get; set; }
    public string? AuthPackage { get; set; }

    /// <summary>Service name and binary, shell resource URI, task name...</summary>
    public string? Detail { get; set; }

    /// <summary>Command lines observed in the session (truncated, " | " separated).</summary>
    public string? Commands { get; set; }

    public int EventCount { get; set; }
    public string? EventIds { get; set; }

    /// <summary>High = direct artifact plus linked logon; Medium = direct artifact; Low = inferred.</summary>
    public string Confidence { get; set; } = "Medium";

    /// <summary>Why the events were grouped, in plain words.</summary>
    public string? Evidence { get; set; }

    public bool IsIoc { get; set; }

    public TimeSpan Duration => End - Start;

    /// <summary>The member events (transient; not persisted).</summary>
    public List<NormalizedEvent> Events { get; } = new();
}
