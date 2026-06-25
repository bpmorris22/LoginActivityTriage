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
/// fields by returning null rather than throwing.
/// </summary>
public sealed class EventXmlData
{
    private readonly Dictionary<string, string> _data;

    public int EventId { get; }
    public string? Provider { get; }
    public long? RecordId { get; }
    public string? Channel { get; }
    public string? Computer { get; }
    public DateTimeOffset? TimeCreated { get; }
    public string RawXml { get; }

    private EventXmlData(
        int eventId, string? provider, long? recordId, string? channel,
        string? computer, DateTimeOffset? timeCreated,
        Dictionary<string, string> data, string rawXml)
    {
        EventId = eventId;
        Provider = provider;
        RecordId = recordId;
        Channel = channel;
        Computer = computer;
        TimeCreated = timeCreated;
        _data = data;
        RawXml = rawXml;
    }

    /// <summary>Value of an &lt;EventData&gt;/&lt;Data Name="..."&gt; element, or null.</summary>
    public string? Get(string name) =>
        _data.TryGetValue(name, out var v) && !string.IsNullOrEmpty(v) ? v : null;

    /// <summary>First non-empty value among the supplied EventData names.</summary>
    public string? GetAny(params string[] names)
    {
        foreach (var n in names)
        {
            var v = Get(n);
            if (v is not null) return v;
        }
        return null;
    }

    public int? GetInt(string name) =>
        int.TryParse(Get(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var i)
            ? i : null;

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
        if (!int.TryParse(eventIdText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
            return null;

        string? provider = system is null
            ? null
            : FindChild(system, "Provider")?.Attributes()
                .FirstOrDefault(a => a.Name.LocalName == "Name")?.Value;

        long? recordId = long.TryParse(
            system is null ? null : ElementValue(system, "EventRecordID"),
            out var rid) ? rid : null;

        string? channel = system is null ? null : ElementValue(system, "Channel");
        string? computer = system is null ? null : ElementValue(system, "Computer");

        DateTimeOffset? time = null;
        var timeEl = system is null ? null : FindChild(system, "TimeCreated");
        var sysTime = timeEl?.Attributes()
            .FirstOrDefault(a => a.Name.LocalName == "SystemTime")?.Value;
        if (DateTimeOffset.TryParse(sysTime, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t))
            time = t;

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var eventData = FindChild(root, "EventData") ?? FindChild(root, "UserData");
        if (eventData is not null)
        {
            // Standard <Data Name="x">value</Data> form.
            foreach (var d in Descendants(eventData, "Data"))
            {
                var name = d.Attributes().FirstOrDefault(a => a.Name.LocalName == "Name")?.Value;
                if (!string.IsNullOrEmpty(name))
                    data[name] = d.Value;
            }
            // UserData form: child elements named after the field (e.g. TS events).
            foreach (var child in eventData.Elements())
            {
                foreach (var leaf in child.Elements())
                {
                    if (!leaf.HasElements && !data.ContainsKey(leaf.Name.LocalName))
                        data[leaf.Name.LocalName] = leaf.Value;
                }
            }
        }

        return new EventXmlData(eventId, provider, recordId, channel, computer, time, data, xml);
    }

    private static XElement? FindChild(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => e.Name.LocalName == localName);

    private static IEnumerable<XElement> Descendants(XElement parent, string localName) =>
        parent.Descendants().Where(e => e.Name.LocalName == localName);

    private static string? ElementValue(XElement parent, string localName) =>
        FindChild(parent, localName)?.Value;
}
