namespace LoginActivityTriage.Core.Mapping;

/// <summary>
/// Translates 4625 / 4776 status and sub-status NTSTATUS codes into the
/// human-readable failure reasons investigators expect to see.
/// </summary>
public static class FailureReasonCatalog
{
    private static readonly IReadOnlyDictionary<string, string> StatusText =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["0xC0000064"] = "User name does not exist",
            ["0xC000006A"] = "Bad password",
            ["0xC000006D"] = "Bad user name or password",
            ["0xC000006E"] = "Account restriction",
            ["0xC000006F"] = "Logon outside permitted hours",
            ["0xC0000070"] = "Workstation restriction",
            ["0xC0000071"] = "Password expired",
            ["0xC0000072"] = "Account disabled",
            ["0xC0000133"] = "Clocks out of sync",
            ["0xC0000193"] = "Account expired",
            ["0xC0000224"] = "Password must change",
            ["0xC0000234"] = "Account locked out",
            ["0xC0000371"] = "No stored credentials",
        };

    public static string? Describe(string? status, string? subStatus)
    {
        var code = FirstMeaningful(subStatus) ?? FirstMeaningful(status);
        if (code is null) return null;
        return StatusText.TryGetValue(code, out var t) ? t : $"Status {code}";
    }

    private static string? FirstMeaningful(string? code)
    {
        if (string.IsNullOrWhiteSpace(code)) return null;
        var trimmed = code.Trim();
        if (trimmed is "0x0" or "0x00000000" or "0") return null;
        return trimmed;
    }
}
