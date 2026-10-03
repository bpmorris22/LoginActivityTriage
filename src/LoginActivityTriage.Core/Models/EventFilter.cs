using LoginActivityTriage.Core.Mapping;

namespace LoginActivityTriage.Core.Models;

/// <summary>
/// Filter criteria applied to the logon timeline. Null / empty members mean
/// "do not filter on this dimension". <see cref="Matches"/> is the single source
/// of truth; the storage layer pre-filters coarsely in SQL and then applies it.
/// </summary>
public sealed class EventFilter
{
    /// <summary>Inclusive lower bound, UTC.</summary>
    public DateTimeOffset? From { get; set; }
    /// <summary>Inclusive upper bound, UTC.</summary>
    public DateTimeOffset? To { get; set; }
    public int? EventId { get; set; }
    public string? User { get; set; }
    public string? Host { get; set; }
    /// <summary>Exact address, CIDR ("10.0.0.0/8"), prefix ("10.0.*") or substring.</summary>
    public string? SourceIp { get; set; }
    public int? LogonType { get; set; }
    public string? AuthPackage { get; set; }
    public string? Technique { get; set; }
    public bool? Success { get; set; }
    public bool PrivilegedOnly { get; set; }
    public bool RdpOnly { get; set; }
    public bool RemoteExecOnly { get; set; }
    public bool ExcludeMachineAccounts { get; set; }
    public bool ExcludeNoiseAccounts { get; set; }
    public bool ExcludeLocalOrBlankSource { get; set; }

    public bool IsEmpty =>
        From is null && To is null && EventId is null &&
        string.IsNullOrWhiteSpace(User) && string.IsNullOrWhiteSpace(Host) &&
        string.IsNullOrWhiteSpace(SourceIp) && LogonType is null &&
        string.IsNullOrWhiteSpace(AuthPackage) && string.IsNullOrWhiteSpace(Technique) && Success is null &&
        !PrivilegedOnly && !RdpOnly && !RemoteExecOnly && !ExcludeMachineAccounts &&
        !ExcludeNoiseAccounts && !ExcludeLocalOrBlankSource;

    public bool Matches(NormalizedEvent e)
    {
        if (From is not null && e.Timestamp < From) return false;
        if (To is not null && e.Timestamp > To) return false;
        if (EventId is not null && e.EventId != EventId) return false;
        if (LogonType is not null && e.LogonType != LogonType) return false;
        if (Success is true && !e.IsSuccess) return false;
        if (Success is false && !e.IsFailure) return false;
        if (PrivilegedOnly && !e.IsPrivileged) return false;
        if (RdpOnly && !e.IsRdp) return false;
        if (RemoteExecOnly && (e.Technique is null || e.Technique == RemoteTechnique.Rdp)) return false;
        if (ExcludeMachineAccounts && e.IsMachineAccount) return false;
        if (ExcludeNoiseAccounts && e.IsNoiseAccount) return false;
        if (ExcludeLocalOrBlankSource && e.IsLocalOrBlankSource) return false;
        if (!Contains(e.TargetUserName, User) && !Contains(e.SubjectUserName, User)) return false;
        if (!Contains(e.Hostname, Host)) return false;
        if (!IpUtil.MatchesFilter(e.SourceIp, SourceIp)) return false;
        if (!Contains(e.AuthenticationPackage, AuthPackage)) return false;
        if (!Contains(e.Technique, Technique)) return false;
        return true;
    }

    private static bool Contains(string? value, string? needle)
    {
        if (string.IsNullOrWhiteSpace(needle)) return true;
        return value is not null &&
               value.Contains(needle.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
