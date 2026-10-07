namespace LoginActivityTriage.Core.Mapping;

/// <summary>
/// Friendly names for the Security / System event IDs handled by the triage tool. Event IDs
/// collide across providers (1102 is "audit log cleared" in Security but an RDP-client event
/// elsewhere), so each normaliser owns the names for its own provider; this catalog holds the
/// Security and System sets.
/// </summary>
public static class WindowsEventCatalog
{
    private static readonly IReadOnlyDictionary<int, string> SecurityNames =
        new Dictionary<int, string>
        {
            [1100] = "Event logging service shut down",
            [1102] = "Security audit log cleared",
            [4608] = "Windows is starting up",
            [4609] = "Windows is shutting down",
            [4624] = "Successful logon",
            [4625] = "Failed logon",
            [4634] = "Logoff",
            [4647] = "User initiated logoff",
            [4648] = "Explicit credentials used",
            [4672] = "Special privileges assigned",
            [4688] = "Process created",
            [4697] = "Service installed (Security)",
            [4698] = "Scheduled task created",
            [4699] = "Scheduled task deleted",
            [4702] = "Scheduled task updated",
            [4720] = "User account created",
            [4722] = "User account enabled",
            [4723] = "Password change attempted",
            [4724] = "Password reset attempted",
            [4725] = "User account disabled",
            [4726] = "User account deleted",
            [4728] = "Added to global security group",
            [4729] = "Removed from global security group",
            [4732] = "Added to local security group",
            [4733] = "Removed from local security group",
            [4740] = "User account locked out",
            [4756] = "Added to universal security group",
            [4757] = "Removed from universal security group",
            [4781] = "User account renamed",
            [4768] = "Kerberos TGT requested",
            [4769] = "Kerberos service ticket requested",
            [4771] = "Kerberos pre-auth failed",
            [4776] = "NTLM credential validation",
            [4778] = "Session reconnected (window station)",
            [4779] = "Session disconnected (window station)",
            [5140] = "Network share accessed",
            [5145] = "Network share object checked",
        };

    private static readonly IReadOnlyDictionary<int, string> SystemNames =
        new Dictionary<int, string>
        {
            [41] = "Rebooted without a clean shutdown (Kernel-Power)",
            [104] = "Event log cleared",
            [1074] = "Shutdown / restart initiated",
            [6005] = "Event log service started (boot)",
            [6006] = "Event log service stopped (clean shutdown)",
            [6008] = "Previous shutdown was unexpected",
            [7036] = "Service state changed",
            [7040] = "Service start type changed",
            [7045] = "Service installed",
        };

    public static IReadOnlyCollection<int> SecurityEventIds => (IReadOnlyCollection<int>)SecurityNames.Keys;
    public static IReadOnlyCollection<int> SystemEventIds => (IReadOnlyCollection<int>)SystemNames.Keys;

    public static string DescribeSecurity(int eventId) =>
        SecurityNames.TryGetValue(eventId, out var n) ? n : $"Security event {eventId}";

    public static string DescribeSystem(int eventId) =>
        SystemNames.TryGetValue(eventId, out var n) ? n : $"System event {eventId}";
}
