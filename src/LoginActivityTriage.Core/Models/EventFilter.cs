namespace LoginActivityTriage.Core.Models;

/// <summary>
/// Filter criteria applied to the logon timeline. Null / empty members mean
/// "do not filter on this dimension". Evaluated both in SQL (storage layer)
/// and in-memory (Matches) so the same semantics drive both.
/// </summary>
public sealed class EventFilter
{
    public DateTimeOffset? From { get; set; }
    public DateTimeOffset? To { get; set; }
    public int? EventId { get; set; }
    public string? User { get; set; }
    public string? Host { get; set; }
    public string? SourceIp { get; set; }
    public int? LogonType { get; set; }
    public string? AuthPackage { get; set; }
    public bool? Success { get; set; }
    public bool PrivilegedOnly { get; set; }
    public bool RdpOnly { get; set; }
    public bool ExcludeMachineAccounts { get; set; }
    public bool ExcludeLocalOrBlankSource { get; set; }

    public bool IsEmpty =>
        From is null && To is null && EventId is null &&
        string.IsNullOrWhiteSpace(User) && string.IsNullOrWhiteSpace(Host) &&
        string.IsNullOrWhiteSpace(SourceIp) && LogonType is null &&
        string.IsNullOrWhiteSpace(AuthPackage) && Success is null &&
        !PrivilegedOnly && !RdpOnly && !ExcludeMachineAccounts && !ExcludeLocalOrBlankSource;

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
        if (ExcludeMachineAccounts && e.IsMachineAccount) return false;
        if (ExcludeLocalOrBlankSource && e.IsLocalOrBlankSource) return false;
        if (!Contains(e.TargetUserName, User)) return false;
        if (!Contains(e.Hostname, Host)) return false;
        if (!Contains(e.SourceIp, SourceIp)) return false;
        if (!Contains(e.AuthenticationPackage, AuthPackage)) return false;
        return true;
    }

    private static bool Contains(string? value, string? needle)
    {
        if (string.IsNullOrWhiteSpace(needle)) return true;
        return value is not null &&
               value.Contains(needle.Trim(), StringComparison.OrdinalIgnoreCase);
    }
}
