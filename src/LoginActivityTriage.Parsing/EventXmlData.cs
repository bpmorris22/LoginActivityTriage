using System.Globalization;
using System.Xml.Linq;

namespace LoginActivityTriage.Parsing;

/// <summary>
/// Tolerant reader over a single Windows event rendered as XML. Works on the
/// XML string produced by <c>EventRecord.ToXml()</c> so the normalisation logic
/// is fully unit-testable without touching the EVTX APIs.
///
/// Matching is done on element local-names so a missing / different default
/// namespace never breaks extraction, and every accessor tolerates absent
/// fields by returning null rather than throwing. The Security-log placeholder
/// "-" is treated as absent.
/// </summary>
public sealed class EventXmlData
{
    private readonly Dictionary<string, string> _data;
    private readonly List<string> _positional;

    public int EventId { get; }
    public string? Provider { get; }
    public long? RecordId { get; }
    public string? Channel { get; }
    public string? Computer { get; }
    public DateTimeOffset? TimeCreated { get; }

    /// <summary>System/Security@UserID — the SID the event was logged under (7045 installer, WinRM user...).</summary>
    public string? UserSid { get; }

    /// <summary>System/Keywords, e.g. 0x8010000000000000 (Security audit failure).</summary>
    public string? Keywords { get; private init; }

    /// <summary>True when the Security record is an Audit Failure (keyword bit 0x0010000000000000).</summary>
    public bool IsAuditFailure =>
        Keywords is not null && Keywords.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
        ulong.TryParse(Keywords[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var k) &&
        (k & 0x0010000000000000UL) != 0;

    public string RawXml { get; }

    private EventXmlData(
        int eventId, string? provider, long? recordId, string? channel,
        string? computer, DateTimeOffset? timeCreated, string? userSid,
        Dictionary<string, string> data, List<string> positional, string rawXml)
    {
        EventId = eventId;
        Provider = provider;
        RecordId = recordId;
        Channel = channel;
        Computer = computer;
        TimeCreated = timeCreated;
        UserSid = userSid;
        _data = data;
        _positional = positional;
        RawXml = rawXml;
    }

    /// <summary>Value of an &lt;EventData&gt;/&lt;Data Name="..."&gt; (or UserData leaf) element, or null.</summary>
    public string? Get(string name) =>
        _data.TryGetValue(name, out var v) ? Clean(v) : null;

    /// <summary>First non-empty value among the supplied names.</summary>
    public string? GetAny(params string[] names)
    {
        foreach (var n in names)
        {
            var v = Get(n);
            if (v is not null) return v;
        }
        return null;
    }

    /// <summary>Unnamed &lt;Data&gt; element by position (classic providers such as "Windows PowerShell").</summary>
    public string? GetPositional(int index) =>
        index >= 0 && index < _positional.Count ? Clean(_positional[index]) : null;

    public int PositionalCount => _positional.Count;

    /// <summary>Every data value (named and positional), for pattern scans.</summary>
    public IEnumerable<string> AllValues => _data.Values.Concat(_positional);

    public int? GetInt(string name)
    {
        var v = Get(name);
        if (v is null) return null;
        if (int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out var i)) return i;
        if (v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(v[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h)) return h;
        return null;
    }

    public bool ProviderIs(string name) =>
        string.Equals(Provider, name, StringComparison.OrdinalIgnoreCase);

    public bool ProviderContains(string fragment) =>
        Provider is not null && Provider.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    public bool ChannelIs(string name) =>
        string.Equals(Channel, name, StringComparison.OrdinalIgnoreCase);

    public bool ChannelContains(string fragment) =>
        Channel is not null && Channel.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    private static string? Clean(string? v)
    {
        if (string.IsNullOrEmpty(v)) return null;
        var t = v.Trim();
        return t.Length == 0 || t == "-" ? null : t;
    }

    /// <summary>
    /// Parses an event XML string. Returns null on malformed XML or when the
    /// EventID cannot be determined, so callers can skip-and-continue.
    /// </summary>
    public static EventXmlData? TryParse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch
        {
            return null;
        }

        var root = doc.Root;
        if (root is null) return null;

        var system = FindChild(root, "System");
        var eventIdText = system is null ? null : ElementValue(system, "EventID");
        if (!int.TryParse(eventIdText?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
            return null;

        string? provider = system is null
            ? null
            : Attr(FindChild(system, "Provider"), "Name");

        long? recordId = long.TryParse(
            system is null ? null : ElementValue(system, "EventRecordID"),
            NumberStyles.Integer, CultureInfo.InvariantCulture, out var rid) ? rid : null;

        string? channel = system is null ? null : ElementValue(system, "Channel");
        string? computer = system is null ? null : ElementValue(system, "Computer");
        string? userSid = system is null ? null : Attr(FindChild(system, "Security"), "UserID");

        DateTimeOffset? time = null;
        var sysTime = system is null ? null : Attr(FindChild(system, "TimeCreated"), "SystemTime");
        if (DateTimeOffset.TryParse(sysTime, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            time = t;

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        var eventData = FindChild(root, "EventData") ?? FindChild(root, "UserData");
        if (eventData is not null)
        {
            // Standard <Data Name="x">value</Data> form; unnamed <Data> are kept positionally.
            foreach (var d in Descendants(eventData, "Data"))
            {
                var name = Attr(d, "Name");
                if (!string.IsNullOrEmpty(name))
                    data[name] = d.Value;
                else
                    positional.Add(d.Value);
            }
            // UserData form: child elements named after the field (TS, Eventlog 1102/104...).
            foreach (var child in eventData.Elements())
            {
                foreach (var leaf in child.Elements())
                {
                    if (!leaf.HasElements && !data.ContainsKey(leaf.Name.LocalName))
                        data[leaf.Name.LocalName] = leaf.Value;
                }
            }
        }

        return new EventXmlData(eventId, provider, recordId, channel?.Trim(), computer?.Trim(), time,
            userSid, data, positional, xml)
        {
            Keywords = system is null ? null : ElementValue(system, "Keywords")?.Trim(),
        };
    }

    private static string? Attr(XElement? el, string localName) =>
        el?.Attributes().FirstOrDefault(a => a.Name.LocalName == localName)?.Value;

    private static XElement? FindChild(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName);

    private static IEnumerable<XElement> Descendants(XElement parent, string localName) =>
        parent.Descendants().Where(e => e.Name.LocalName == localName);

    private static string? ElementValue(XElement parent, string localName) =>
        FindChild(parent, localName)?.Value;
}
