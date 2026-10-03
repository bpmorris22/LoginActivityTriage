using System.Collections.ObjectModel;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.App.ViewModels;

/// <summary>
/// Backing model for the Logon Story window: every event related to a chosen pivot
/// (user / source IP / host / remote session) inside a configurable time window, ordered
/// chronologically. Users and hosts compare on normalised keys, so "CONTOSO\jdoe" matches
/// "jdoe" and "HOST01.contoso.local" matches "HOST01".
/// </summary>
public sealed class LogonStoryViewModel : Mvvm.ObservableObject
{
    public string Title { get; }
    public string PivotDescription { get; }
    public DateTimeOffset Anchor { get; }
    public int WindowMinutes { get; }
    public ObservableCollection<NormalizedEvent> Events { get; }

    public LogonStoryViewModel(
        string title, string pivotDescription, DateTimeOffset anchor,
        int windowMinutes, IEnumerable<NormalizedEvent> events)
    {
        Title = title;
        PivotDescription = pivotDescription;
        Anchor = anchor;
        WindowMinutes = windowMinutes;
        Events = new ObservableCollection<NormalizedEvent>(events);
    }

    /// <summary>Every event sharing the anchor's user, source IP or host within +/- windowMinutes.</summary>
    public static LogonStoryViewModel BuildForEvent(
        NormalizedEvent anchor, IEnumerable<NormalizedEvent> all, int windowMinutes)
    {
        var from = anchor.Timestamp.AddMinutes(-windowMinutes);
        var to = anchor.Timestamp.AddMinutes(windowMinutes);
        var ip = IpUtil.IsLocalOrBlank(anchor.SourceIp) ? null : anchor.SourceIp;

        bool Related(NormalizedEvent e) =>
            UserKey.Same(e.TargetUserName, anchor.TargetUserName) ||
            UserKey.Same(e.SubjectUserName, anchor.TargetUserName) ||
            (ip is not null && string.Equals(e.SourceIp, ip, StringComparison.OrdinalIgnoreCase)) ||
            HostKey.Same(e.Hostname, anchor.Hostname) ||
            (anchor.RemoteSessionRef is not null && e.RemoteSessionRef == anchor.RemoteSessionRef);

        var events = all
            .Where(e => e.Timestamp >= from && e.Timestamp <= to && Related(e))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var pivot = $"User: {anchor.TargetUserName ?? "-"}   Source IP: {anchor.SourceIp ?? "-"}   Host: {anchor.Hostname ?? "-"}";
        var title = $"Logon Story +/-{windowMinutes}m around {anchor.Timestamp.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z";
        return new LogonStoryViewModel(title, pivot, anchor.Timestamp, windowMinutes, events);
    }

    /// <summary>The member events of one stitched remote session.</summary>
    public static LogonStoryViewModel BuildForSession(RemoteSession s)
    {
        var title = $"Session #{s.Id}: {s.Technique}{(s.Variant is null ? "" : $" ({s.Variant})")} {s.Direction}";
        var pivot = $"Host: {s.Host}   User: {s.User ?? "-"}   Source: {s.SourceIp ?? s.SourceHost ?? "-"}   " +
                    $"Confidence: {s.Confidence}   {s.Evidence}";
        return new LogonStoryViewModel(title, pivot, s.Start, (int)Math.Ceiling(s.Duration.TotalMinutes),
            s.Events.OrderBy(e => e.Timestamp));
    }

    /// <summary>Builds a story around a free-form pivot value (user, IP or host).</summary>
    public static LogonStoryViewModel BuildForPivot(
        string pivotKind, string pivotValue, IEnumerable<NormalizedEvent> all,
        DateTimeOffset anchor, int windowMinutes)
    {
        var from = anchor.AddMinutes(-windowMinutes);
        var to = anchor.AddMinutes(windowMinutes);

        bool Match(NormalizedEvent e) => pivotKind switch
        {
            "user" => UserKey.Same(e.TargetUserName, pivotValue) || UserKey.Same(e.SubjectUserName, pivotValue),
            "ip"   => string.Equals(e.SourceIp, pivotValue, StringComparison.OrdinalIgnoreCase),
            "host" => HostKey.Same(e.Hostname, pivotValue),
            _      => false,
        };

        var events = all
            .Where(e => e.Timestamp >= from && e.Timestamp <= to && Match(e))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var title = $"Logon Story for {pivotKind} '{pivotValue}' +/-{windowMinutes}m";
        return new LogonStoryViewModel(title, $"{pivotKind}: {pivotValue}", anchor, windowMinutes, events);
    }
}
