using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Export;
using LoginActivityTriage.Parsing;

namespace LoginActivityTriage.Cli;

/// <summary>
/// Headless front end: EVTX (folder, file or live logs) → normalised events, stitched remote
/// sessions, findings and pivots as CSV + summary.json. Driven by the HTA wrapper, usable on
/// its own. Read-only against the evidence; writes only to the output folder.
/// </summary>
internal static class Program
{
    private const int ExitOk = 0, ExitUsage = 1, ExitNoInput = 2, ExitFatal = 3, ExitUnreadable = 4;

    /// <summary>Every file a run publishes; files of an earlier run that this run did not produce are removed.</summary>
    private static readonly string[] OutputFiles =
    {
        "events.csv", "timeline.csv", "sessions.csv", "findings.csv", "users.csv", "sourceips.csv", "hosts.csv",
        "remotehosts.csv", "files.csv", "report-findings.html", "report-sessions.html", "summary.json",
    };

    /// <summary>Results are written here and moved into the output folder only when the run succeeds.</summary>
    private static string? _stage;

    private static readonly string Version =
        typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0]
        ?? typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    private sealed class Options
    {
        public string? Directory;
        public string? File;
        public bool Live;
        public string? Output;
        public TimeZoneInfo TimeZone = TimeZoneInfo.Utc;   // fallback (or forced zone when AutoTz is false)
        public bool AutoTz = true;                          // per-host zone from System 6013
        public int StartHour = 7, EndHour = 19;
        public bool Weekend = true;
        public bool KeepNoise;
        public DateTimeOffset? From, To;
        public bool Quiet;
        public bool Html = true;
        public bool Hash = true;                            // SHA-256 of every source file into files.csv
    }

    private static TextWriter? _log;

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0 || args.Any(a => a is "-h" or "--help" or "/?"))
        {
            Usage();
            return args.Length == 0 ? ExitUsage : ExitOk;
        }
        if (args.Any(a => a is "-v" or "--version"))
        {
            Console.WriteLine($"LoginActivityTriageCli {Version}");
            return ExitOk;
        }

        Options o;
        try { o = Parse(args); }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine("Error: " + ex.Message);
            Console.Error.WriteLine("Run with --help for usage.");
            return ExitUsage;
        }

        try
        {
            return Run(o);
        }
        catch (Exception ex)
        {
            Say("FATAL: " + ex);
            Say("Previous results in the output folder (if any) were left unchanged.");
            return ExitFatal;
        }
        finally
        {
            DiscardStage();
            _log?.Dispose();
        }
    }

    private static void DiscardStage()
    {
        try { if (_stage is not null && Directory.Exists(_stage)) Directory.Delete(_stage, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Moves a completed run's files from the staging folder into the output folder, summary.json
    /// last, so a summary only ever describes a complete set from the same run. Refuses (leaving the
    /// previous results untouched) when a destination file is open in another program.
    /// </summary>
    private static void Publish(string stage, string outDir)
    {
        var locked = new List<string>();
        foreach (var name in OutputFiles)
        {
            var dest = Path.Combine(outDir, name);
            if (!File.Exists(dest)) continue;
            try { using var _ = new FileStream(dest, FileMode.Open, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { locked.Add(name); }
            catch (UnauthorizedAccessException) { locked.Add(name); }
        }
        if (locked.Count > 0)
            throw new IOException($"{string.Join(", ", locked)} is open in another program (Timeline Explorer, Excel...). " +
                                  "Close it and run again.");

        foreach (var name in OutputFiles.Where(n => n != "summary.json"))
        {
            var src = Path.Combine(stage, name);
            var dest = Path.Combine(outDir, name);
            if (File.Exists(src)) File.Move(src, dest, overwrite: true);
            else if (File.Exists(dest)) File.Delete(dest); // not produced by this run (e.g. --no-html)
        }
        File.Move(Path.Combine(stage, "summary.json"), Path.Combine(outDir, "summary.json"), overwrite: true);
    }

    private static int Run(Options o)
    {
        Directory.CreateDirectory(o.Output!);
        _log = new StreamWriter(Path.Combine(o.Output!, "run.log"), append: false, new UTF8Encoding(false)) { AutoFlush = true };
        var sw = Stopwatch.StartNew();
        var input = o.Live ? "(live event logs)" : o.Directory ?? o.File!;
        Say($"Login Activity Triage CLI {Version}");
        Say($"Input   : {input}");
        Say($"Output  : {o.Output}");
        Say($"Hours   : {o.StartHour:00}:00-{o.EndHour:00}:00 {(o.AutoTz ? "in each host's own zone (System 6013), UTC where unknown" : o.TimeZone.Id)}{(o.Weekend ? " (weekends = after hours)" : "")}");
        Say($"Noise   : {(o.KeepNoise ? "kept" : "machine / system-account logon noise dropped")}");

        if (!o.Live && EvtxImporter.DiscoverEvtxFiles(input).Count == 0)
        {
            Say("No .evtx files found at the input path.");
            return ExitNoInput;
        }

        var events = new List<NormalizedEvent>();
        var importer = new EvtxImporter();
        var importOptions = new ImportOptions
        {
            From = o.From,
            To = o.To,
            Keep = o.KeepNoise ? null : e => !NoiseFilter.IsRoutineNoise(e),
            HashFiles = o.Hash,
        };
        Say($"Hashes  : {(o.Hash && !o.Live ? "SHA-256 and size of every source file recorded in files.csv" : "not recorded")}");
        var lastFile = -1;
        var progress = new SyncProgress<ImportProgress>(p =>
        {
            if (p.FileIndex == lastFile || string.IsNullOrEmpty(p.CurrentFile)) return;
            lastFile = p.FileIndex;
            Say($"[{p.FileIndex + 1}/{p.FileCount}] {p.CurrentFile}  ({p.EventsNormalisedSoFar:N0} events so far)", quiet: o.Quiet);
        });

        void Sink(NormalizedEvent e)
        {
            e.RawXml = null; // not exported; keeps memory flat on large logs
            events.Add(e);
        }

        var summary = o.Live
            ? importer.ImportLive(Sink, progress, default, importOptions)
            : importer.Import(input, Sink, progress, default, importOptions);

        var before = events.Count;
        events = ProcessEventFilter.Apply(events);
        var processDropped = before - events.Count;
        events.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));

        Say($"Imported {events.Count:N0} event(s) from {summary.FilesProcessed} source(s); " +
            $"{summary.TotalDuplicates:N0} duplicate(s), {summary.TotalFiltered:N0} filtered, " +
            $"{processDropped:N0} unrelated process event(s) dropped, {summary.TotalSkipped:N0} unreadable record(s).");
        foreach (var err in summary.Errors) Say("  ! " + err);
        if (summary.FilesProcessed > 0 && summary.FilesFailed == summary.FilesProcessed)
        {
            Say($"None of the {summary.FilesProcessed} input source(s) could be read (see above). No results were written; " +
                "previous results in the output folder (if any) were left unchanged.");
            return ExitUnreadable;
        }
        if (summary.FilesFailed > 0)
            Say($"WARNING: {summary.FilesFailed} of {summary.FilesProcessed} source(s) could not be read; results cover the rest.");

        Say("Analysing...");
        var analyzer = new SuspiciousSequenceAnalyzer(new AnalyzerOptions
        {
            TimeZone = o.TimeZone,
            UseHostTimeZones = o.AutoTz,
            BusinessStartHour = o.StartHour,
            BusinessEndHour = o.EndHour,
            WeekendIsAfterHours = o.Weekend,
        });
        var result = analyzer.Run(events);

        _stage = Path.Combine(o.Output!, ".lat-staging");
        DiscardStage();
        Directory.CreateDirectory(_stage);
        var outDir = _stage;
        var timeline = events.Where(TriageTimeline.Include).ToList();
        CsvExporter.Write(Path.Combine(outDir, "events.csv"), events, CsvExporter.EventColumns);
        CsvExporter.Write(Path.Combine(outDir, "timeline.csv"), timeline, CsvExporter.EventColumns);
        Say($"Triage timeline: {timeline.Count:N0} of {events.Count:N0} events (routine network / DC authentication and WinRM client errors outside sessions are in events.csv only).");
        CsvExporter.Write(Path.Combine(outDir, "sessions.csv"), result.Sessions, CsvExporter.SessionColumns);
        CsvExporter.Write(Path.Combine(outDir, "findings.csv"), result.Findings, CsvExporter.FindingColumns);
        CsvExporter.Write(Path.Combine(outDir, "users.csv"), PivotBuilder.ByUser(events), CsvExporter.UserPivotColumns);
        CsvExporter.Write(Path.Combine(outDir, "sourceips.csv"), PivotBuilder.BySourceIp(events), CsvExporter.SourceIpPivotColumns);
        CsvExporter.Write(Path.Combine(outDir, "hosts.csv"), PivotBuilder.ByHost(events), CsvExporter.HostPivotColumns);
        CsvExporter.Write(Path.Combine(outDir, "remotehosts.csv"), PivotBuilder.ByRemoteHost(events, result.Sessions), CsvExporter.RemoteHostPivotColumns);
        CsvExporter.Write(Path.Combine(outDir, "files.csv"), summary.Files, CsvExporter.FileColumns);
        if (o.Html)
        {
            HtmlExporter.ExportFindings(result.Findings, Path.Combine(outDir, "report-findings.html"), "Login Activity Triage - Findings");
            HtmlExporter.ExportSessions(result.Sessions, Path.Combine(outDir, "report-sessions.html"), "Login Activity Triage - Remote Sessions");
        }

        WriteSummary(Path.Combine(outDir, "summary.json"), o, input, summary, events, result, processDropped, sw.Elapsed, timeline.Count);
        Publish(_stage, o.Output!);

        Say($"Sessions: {result.Sessions.Count:N0}  " +
            string.Join("  ", result.Sessions.GroupBy(s => $"{s.Technique}{(s.Direction == "Outbound" ? " out" : "")}")
                .OrderByDescending(g => g.Count()).Select(g => $"{g.Key}={g.Count()}")));
        Say($"Findings: {result.Findings.Count:N0}  " +
            string.Join("  ", result.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key).Select(g => $"{g.Key}={g.Count()}")));
        Say($"Done in {sw.Elapsed.TotalSeconds:0.0}s. Results written to {o.Output}");
        return ExitOk;
    }

    private static void WriteSummary(string path, Options o, string input, ImportSummary import,
        List<NormalizedEvent> events, AnalysisResult result, int processDropped, TimeSpan elapsed, int timelineCount)
    {
        var hosts = events.Where(e => e.Hostname is not null)
            .GroupBy(e => LoginActivityTriage.Core.Mapping.HostKey.Of(e.Hostname))
            .Select(g => new
            {
                host = g.Key,
                events = g.Count(),
                first = CsvExporter.Ts(g.Min(e => e.Timestamp)),
                last = CsvExporter.Ts(g.Max(e => e.Timestamp)),
                logSources = g.Select(e => e.LogSource).Where(s => s is not null).Distinct().OrderBy(s => s).ToArray(),
            })
            .OrderByDescending(h => h.events).ToArray();

        var doc = new
        {
            tool = "LoginActivityTriageCli",
            version = Version,
            generatedUtc = CsvExporter.Ts(DateTimeOffset.UtcNow),
            elapsedSeconds = Math.Round(elapsed.TotalSeconds, 1),
            input,
            mode = o.Live ? "live" : o.File is not null ? "file" : "directory",
            machine = Environment.MachineName,
            timeZone = o.AutoTz ? "auto" : o.TimeZone.Id,
            hostTimeZones = result.HostZones.ToDictionary(kv => kv.Key, kv => kv.Value.Id),
            businessHours = $"{o.StartHour:00}:00-{o.EndHour:00}:00",
            weekendIsAfterHours = o.Weekend,
            noiseDropped = !o.KeepNoise,
            fileHashes = o.Hash && !o.Live ? "SHA-256" : null,
            from = o.From is null ? null : CsvExporter.Ts(o.From.Value),
            to = o.To is null ? null : CsvExporter.Ts(o.To.Value),
            files = import.FilesProcessed,
            filesFailed = import.FilesFailed,
            recordsRead = import.TotalRecordsRead,
            eventsKept = events.Count,
            timelineEvents = timelineCount,
            duplicates = import.TotalDuplicates,
            filtered = import.TotalFiltered,
            unrelatedProcessEventsDropped = processDropped,
            unreadableRecords = import.TotalSkipped,
            firstEvent = events.Count == 0 ? null : CsvExporter.Ts(events[0].Timestamp),
            lastEvent = events.Count == 0 ? null : CsvExporter.Ts(events[^1].Timestamp),
            hosts,
            sessions = result.Sessions.GroupBy(s => new { s.Technique, s.Direction })
                .Select(g => new { technique = g.Key.Technique, direction = g.Key.Direction, count = g.Count() })
                .OrderByDescending(x => x.count).ToArray(),
            findings = result.Findings.GroupBy(f => f.Severity).OrderByDescending(g => g.Key)
                .ToDictionary(g => g.Key.ToString(), g => g.Count()),
            errors = import.Errors,
        };
        File.WriteAllText(path, JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }),
            new UTF8Encoding(false));
    }

    // ------------------------------------------------------------------ args

    private static Options Parse(string[] args)
    {
        var o = new Options();
        for (var i = 0; i < args.Length; i++)
        {
            var a = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{a} needs a value.");
            switch (a.ToLowerInvariant())
            {
                case "-d": case "--directory": o.Directory = Next(); break;
                case "-f": case "--file": o.File = Next(); break;
                case "--live": o.Live = true; break;
                case "-o": case "--output": o.Output = Next(); break;
                case "--tz":
                {
                    var tz = Next();
                    o.AutoTz = tz.Equals("auto", StringComparison.OrdinalIgnoreCase);
                    if (!o.AutoTz) o.TimeZone = ParseTz(tz);
                    break;
                }
                case "--hours": (o.StartHour, o.EndHour) = ParseHours(Next()); break;
                case "--no-weekend": o.Weekend = false; break;
                case "--keep-noise": o.KeepNoise = true; break;
                case "--from": o.From = ParseUtc(Next()); break;
                case "--to": o.To = ParseUtc(Next()); break;
                case "-q": case "--quiet": o.Quiet = true; break;
                case "--no-html": o.Html = false; break;
                case "--no-hash": o.Hash = false; break;
                default: throw new ArgumentException($"Unknown argument '{a}'.");
            }
        }

        var inputs = (o.Directory is null ? 0 : 1) + (o.File is null ? 0 : 1) + (o.Live ? 1 : 0);
        if (inputs != 1) throw new ArgumentException("Give exactly one of -d <folder>, -f <file.evtx> or --live.");
        if (o.Output is null) throw new ArgumentException("-o <output folder> is required.");
        if (o.Directory is not null && !System.IO.Directory.Exists(o.Directory)) throw new ArgumentException($"Folder not found: {o.Directory}");
        if (o.File is not null && !System.IO.File.Exists(o.File)) throw new ArgumentException($"File not found: {o.File}");
        o.Directory = o.Directory is null ? null : Path.GetFullPath(o.Directory);
        o.File = o.File is null ? null : Path.GetFullPath(o.File);
        o.Output = Path.GetFullPath(o.Output);
        return o;
    }

    private static TimeZoneInfo ParseTz(string id)
    {
        try { return LoginActivityTriage.Core.Mapping.TimeZoneUtil.Parse(id); }
        catch (ArgumentException)
        {
            throw new ArgumentException($"Unknown time zone '{id}' (use auto, a Windows id such as \"Taipei Standard Time\", " +
                                        "an IANA id such as Asia/Taipei, a fixed offset such as UTC+08:00, 'local' or 'utc').");
        }
    }

    /// <summary>"7-19" is an ordinary day; "22-6" is a shift that crosses midnight (business hours 22:00-06:00).</summary>
    private static (int, int) ParseHours(string v)
    {
        var parts = v.Split('-');
        if (parts.Length == 2 && int.TryParse(parts[0], out var s) && int.TryParse(parts[1], out var e) &&
            s is >= 0 and <= 23 && e is >= 0 and <= 24 && s != e)
            return (s, e);
        throw new ArgumentException("--hours expects START-END in whole hours, e.g. 7-19 (or 22-6 for a shift that crosses midnight).");
    }

    private static DateTimeOffset ParseUtc(string v) =>
        DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
            ? t
            : throw new ArgumentException($"Cannot parse date/time '{v}' (use ISO-8601, e.g. 2026-06-20T08:00:00Z).");

    private static void Usage()
    {
        Console.WriteLine($@"Login Activity Triage CLI {Version}
Triage Windows authentication and remote-access activity (RDP, PsExec, PowerShell Remoting,
WMI, scheduled tasks...) from EVTX files. Read-only; writes CSV + JSON to the output folder.

Usage:
  LoginActivityTriageCli -d <folder>      -o <outDir> [options]   recurse a folder of .evtx (KAPE / Velociraptor trees)
  LoginActivityTriageCli -f <file.evtx>   -o <outDir> [options]   one EVTX file
  LoginActivityTriageCli --live           -o <outDir> [options]   this machine's live logs (run elevated)

Options:
  --tz <id>          Zone for the business-hours rule. Default 'auto': each host's own UTC
                     offset from its System 6013 events (UTC where none). Or force one zone:
                     Windows id (""Taipei Standard Time""), IANA id (Asia/Taipei), fixed
                     offset (UTC+08:00), 'local' (this machine) or 'utc'.
  --hours 7-19       Business hours in that time zone (default 7-19; 22-6 = a shift across midnight).
  --no-weekend       Do not treat Saturday / Sunday as after hours.
  --keep-noise       Keep machine-account / SYSTEM / service logon, logoff and ticket events.
  --from <utc>       Only events at or after this ISO-8601 time.
  --to <utc>         Only events at or before this ISO-8601 time.
  --no-html          Skip the HTML reports.
  --no-hash          Do not record the SHA-256 and size of each source file in files.csv.
  -q, --quiet        Do not print per-file progress.
  -v, --version      Print the version.

Outputs (UTF-8 CSV, all timestamps ISO-8601 UTC with Z):
  events.csv  timeline.csv  sessions.csv  findings.csv  users.csv  sourceips.csv  hosts.csv  remotehosts.csv  files.csv
  summary.json  run.log  report-findings.html  report-sessions.html

Results are staged and published only when the run succeeds; on any failure the output
folder keeps the previous run's files (run.log always describes the latest attempt).

Exit codes: 0 ok, 1 usage error, 2 no EVTX found, 3 fatal error, 4 no input could be read.");
    }

    private static void Say(string line, bool quiet = false)
    {
        if (!quiet) Console.WriteLine(line);
        _log?.WriteLine(line);
    }

    /// <summary>IProgress that invokes synchronously on the reporting thread (no sync context in a console).</summary>
    private sealed class SyncProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }
}
