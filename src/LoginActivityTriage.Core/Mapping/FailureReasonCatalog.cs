namespace LoginActivityTriage.Core.Mapping;

/// <summary>
/// Translates 4625 / 4776 NTSTATUS codes and 4768 / 4769 / 4771 Kerberos result codes
/// into the human-readable failure reasons investigators expect to see.
/// </summary>
public static class FailureReasonCatalog
{
    private static readonly IReadOnlyDictionary<string, string> StatusText =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["0xC0000022"] = "Access denied",
            ["0xC000005E"] = "No logon servers available",
            ["0xC0000064"] = "User name does not exist",
            ["0xC000006A"] = "Bad password",
            ["0xC000006D"] = "Bad user name or password",
            ["0xC000006E"] = "Account restriction",
            ["0xC000006F"] = "Logon outside permitted hours",
            ["0xC0000070"] = "Workstation restriction",
            ["0xC0000071"] = "Password expired",
            ["0xC0000072"] = "Account disabled",
            ["0xC00000DC"] = "Server in wrong state",
            ["0xC0000133"] = "Clocks out of sync",
            ["0xC000015B"] = "Logon type not granted",
            ["0xC000018C"] = "Trust relationship failed",
            ["0xC0000192"] = "NetLogon service not started",
            ["0xC0000193"] = "Account expired",
            ["0xC0000224"] = "Password must change",
            ["0xC0000234"] = "Account locked out",
            ["0xC00002EE"] = "Error during logon",
            ["0xC0000371"] = "No stored credentials",
            ["0xC0000413"] = "Authentication firewall (not allowed to authenticate)",
        };

    private static readonly IReadOnlyDictionary<int, string> KerberosText =
        new Dictionary<int, string>
        {
            [0x6] = "Kerberos: user name not found",
            [0x7] = "Kerberos: service principal not found",
            [0xC] = "Kerberos: policy restriction (workstation / hours)",
            [0xE] = "Kerberos: encryption type not supported",
            [0x12] = "Kerberos: account disabled, expired or locked out",
            [0x17] = "Kerberos: password expired",
            [0x18] = "Kerberos: pre-authentication failed (bad password)",
            [0x1B] = "Kerberos: server requires user-to-user",
            [0x1F] = "Kerberos: integrity check failed",
            [0x20] = "Kerberos: ticket expired",
            [0x25] = "Kerberos: clock skew too great",
            [0x29] = "Kerberos: message modified",
            [0x3C] = "Kerberos: generic error",
        };

    /// <summary>NTSTATUS failure reason (sub-status preferred over status).</summary>
    public static string? Describe(string? status, string? subStatus)
    {
        var code = FirstMeaningful(subStatus) ?? FirstMeaningful(status);
        if (code is null) return null;
        return StatusText.TryGetValue(code, out var t) ? t : $"Status {code}";
    }

    /// <summary>Kerberos result code (0x0 = success, returns null).</summary>
    public static string? DescribeKerberos(string? status)
    {
        var code = ParseHex(status);
        if (code is null or 0) return null;
        return KerberosText.TryGetValue(code.Value, out var t) ? t : $"Kerberos error 0x{code.Value:X}";
    }

    /// <summary>True when a hex status string is zero or absent.</summary>
    public static bool IsZero(string? status) => ParseHex(status) is null or 0;

    private static int? ParseHex(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim();
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) t = t[2..];
        return int.TryParse(t, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : null;
    }

    private static string? FirstMeaningful(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var trimmed = code.Trim();
        if (trimmed is "0x0" or "0x00000000" or "0" or "-") return null;
        return trimmed;
    }
}
