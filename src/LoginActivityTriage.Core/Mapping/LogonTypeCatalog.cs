namespace LoginActivityTriage.Core.Mapping;

/// <summary>
/// Maps Windows logon type numbers to their canonical descriptions.
/// Reference: Security event 4624 / 4625 "Logon Type" field.
/// </summary>
public static class LogonTypeCatalog
{
    private static readonly IReadOnlyDictionary<int, string> Descriptions =
        new Dictionary<int, string>
        {
            [0] = "System",
            [2] = "Interactive",
            [3] = "Network",
            [4] = "Batch",
            [5] = "Service",
            [7] = "Unlock",
            [8] = "NetworkCleartext",
            [9] = "NewCredentials",
            [10] = "RemoteInteractive / RDP",
            [11] = "CachedInteractive",
            [12] = "CachedRemoteInteractive",
            [13] = "CachedUnlock",
        };

    public static string Describe(int? logonType)
    {
        if (logonType is null) return string.Empty;
        return Descriptions.TryGetValue(logonType.Value, out var d)
            ? d
            : $"Unknown ({logonType})";
    }
}
