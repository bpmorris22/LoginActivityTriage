namespace LoginActivityTriage.Core.Mapping;

/// <summary>
/// Friendly names for the Windows Event IDs handled by the triage tool, plus
/// helpers describing whether an event is a success, failure or neutral signal.
/// </summary>
public static class WindowsEventCatalog
{
    private static readonly IReadOnlyDictionary<int, string> Names =
        new Dictionary<int, string>
        {
            [4624] = "Successful logon",
            [4625] = "Failed logon",
            [4634] = "Logoff",
            [4647] = "User initiated logoff",
            [4648] = "Explicit credentials used",
            [4672] = "Special privileges assigned",
            [4720] = "User account created",
            [4722] = "User account enabled",
            [4723] = "Password change attempted",
            [4724] = "Password reset attempted",
            [4726] = "User account deleted",
            [4728] = "Added to global security group",
            [4732] = "Added to local security group",
            [4756] = "Added to universal security group",
            [4768] = "Kerberos TGT request",
            [4769] = "Kerberos service ticket requested",
            [4771] = "Kerberos pre-auth failed",
            [4776] = "NTLM authentication",
            [7045] = "Service installed",
            [1149] = "RDP authentication succeeded",
            [21]   = "Session logon",
            [22]   = "Shell start",
            [24]   = "Session disconnected",
            [25]   = "Session reconnected",
            [39]   = "Session disconnected by session",
            [40]   = "Session disconnect reason",
        };

    public static IReadOnlyCollection<int> KnownEventIds => (IReadOnlyCollection<int>)Names.Keys;
    public static string Describe(int eventId) => Names.TryGetValue(eventId, out var n) ? n : $"Event {eventId}";
    public static bool IsKnown(int eventId) => Names.ContainsKey(eventId);
    public static bool IsFailureEvent(int eventId) => eventId is 4625 or 4771;
    public static bool IsSuccessEvent(int eventId) => eventId is 4624 or 1149;
}
