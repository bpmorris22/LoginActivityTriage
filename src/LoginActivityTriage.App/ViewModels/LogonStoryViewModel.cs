using System.Collections.ObjectModel;
using LoginActivityTriage.Core.Models;

namespace LoginActivityTriage.App.ViewModels;

/// <summary>
/// Backing model for the Logon Story window: every event related to a chosen
/// pivot (user / source IP / host / single event) inside a configurable time
/// window, ordered chronologically.
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

    /// <summary>
    /// Builds a story around an anchor event. Includes every event sharing the
    /// same user, source IP or host within +/- windowMinutes of the anchor.
    /// </summary>
    public static LogonStoryViewModel BuildForEvent(
        NormalizedEvent anchor, IEnumerable<NormalizedEvent> all, int windowMinutes)
    {
        var from = anchor.Timestamp.AddMinutes(-windowMinutes);
        var to = anchor.Timestamp.AddMinutes(windowMinutes);

        bool Related(NormalizedEvent e) =>
            Same(e.TargetUserName, anchor.TargetUserName) ||
            Same(e.SourceIp, anchor.SourceIp) ||
            Same(e.Hostname, anchor.Hostname);

        var events = all
            .Where(e => e.Timestamp >= from && e.Timestamp <= to && Related(e))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var pivot = $"User: {anchor.TargetUserName ?? "-"}   Source IP: {anchor.SourceIp ?? "-"}   Host: {anchor.Hostname ?? "-"}";
        var title = $"Logon Story +/-{windowMinutes}m around {anchor.Timestamp:yyyy-MM-dd HH:mm:ss}";
        return new LogonStoryViewModel(title, pivot, anchor.Timestamp, windowMinutes, events);
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
            "user" => Same(e.TargetUserName, pivotValue),
            "ip"   => Same(e.SourceIp, pivotValue),
            "host" => Same(e.Hostname, pivotValue),
            _      => false,
        };

        var events = all
            .Where(e => e.Timestamp >= from && e.Timestamp <= to && Match(e))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var title = $"Logon Story for {pivotKind} '{pivotValue}' +/-{windowMinutes}m";
        return new LogonStoryViewModel(title, $"{pivotKind}: {pivotValue}", anchor, windowMinutes, events);
    }

    private static bool Same(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) &&
        string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
