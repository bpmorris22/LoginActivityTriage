using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.App.Mvvm;
using LoginActivityTriage.Core.Mapping;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Export;
using LoginActivityTriage.Parsing;
using LoginActivityTriage.Storage;
using Microsoft.Win32;

namespace LoginActivityTriage.App.ViewModels;

/// <summary>
/// Root view model: owns the open case, the in-memory event set, the timeline filter, the
/// dashboard projections, stitched remote sessions and all top-level commands.
///
/// Memory: raw event XML is written to the case database during import and released from
/// memory; the detail pane reloads it on demand for the selected row.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private readonly List<NormalizedEvent> _allEvents = new();

    /// <summary>The current filtered / IOC-restricted subset that feeds every event view.</summary>
    private List<NormalizedEvent> _view = new();

    private List<RemoteSession> _sessions = new();

    private readonly IocSet _iocs = new();

    private CaseStore? _store;
    private CancellationTokenSource? _importCts;

    public RangeObservableCollection<NormalizedEvent> Events { get; } = new();
    public RangeObservableCollection<Finding> Findings { get; } = new();
    public RangeObservableCollection<RemoteSession> RemoteSessions { get; } = new();
    public ObservableCollection<string> ErrorLog { get; } = new();

    public RangeObservableCollection<StatItem> TopUsersSuccess { get; } = new();
    public RangeObservableCollection<StatItem> TopUsersFailed { get; } = new();
    public RangeObservableCollection<StatItem> TopSourceIps { get; } = new();
    public RangeObservableCollection<StatItem> TopHosts { get; } = new();
    public RangeObservableCollection<StatItem> TopPrivilegedUsers { get; } = new();
    public RangeObservableCollection<StatItem> TopRdpSourceIps { get; } = new();

    public RangeObservableCollection<NormalizedEvent> RdpEvents { get; } = new();
    public RangeObservableCollection<NormalizedEvent> FailedEvents { get; } = new();
    public RangeObservableCollection<NormalizedEvent> AdminEvents { get; } = new();
    public RangeObservableCollection<SourceIpPivot> SourceIpPivots { get; } = new();
    public RangeObservableCollection<UserPivot> UserPivots { get; } = new();
    public RangeObservableCollection<HostPivot> HostPivots { get; } = new();

    /// <summary>Raised when a Logon Story should be shown; the view opens the window.</summary>
    public event Action<LogonStoryViewModel>? LogonStoryRequested;

    public MainViewModel()
    {
        NewCaseCommand = new RelayCommand(NewCase, () => !IsBusy);
        ImportFolderCommand = new RelayCommand(ImportFolder, () => !IsBusy);
        CancelImportCommand = new RelayCommand(() => _importCts?.Cancel(), () => IsBusy);
        ApplyFilterCommand = new RelayCommand(ApplyFilter);
        ClearFilterCommand = new RelayCommand(ClearFilter);
        ExportCsvCommand = new RelayCommand(ExportCsv, () => Events.Count > 0);
        ExportHtmlCommand = new RelayCommand(ExportHtml, () => Events.Count > 0);
        ExportReportCommand = new RelayCommand(ExportReport, () => Findings.Count > 0 || RemoteSessions.Count > 0);
        ShowLogonStoryCommand = new RelayCommand(ShowLogonStory);
        ShowSessionEventsCommand = new RelayCommand(ShowSessionEvents);
        QuickFilterCommand = new RelayCommand(p => ApplyQuickFilter(p as string));
        ApplyIocsCommand = new RelayCommand(ApplyIocs);
        ClearIocsCommand = new RelayCommand(ClearIocs);
        StoryWindowMinutes = 30;

        TimeZones = TimeZoneInfo.GetSystemTimeZones().ToList();
        _selectedTimeZone = TimeZones.FirstOrDefault(z => z.Id == TimeZoneInfo.Local.Id) ?? TimeZoneInfo.Utc;
    }

    public RelayCommand NewCaseCommand { get; }
    public RelayCommand ImportFolderCommand { get; }
    public RelayCommand CancelImportCommand { get; }
    public RelayCommand ApplyFilterCommand { get; }
    public RelayCommand ClearFilterCommand { get; }
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportReportCommand { get; }
    public RelayCommand ShowLogonStoryCommand { get; }
    public RelayCommand ShowSessionEventsCommand { get; }
    public RelayCommand QuickFilterCommand { get; }
    public RelayCommand ApplyIocsCommand { get; }
    public RelayCommand ClearIocsCommand { get; }

    // ---- Case / status ----

    private string _caseName = "(no case loaded)";
    public string CaseName { get => _caseName; set => SetProperty(ref _caseName, value); }

    private string _statusText = "Ready. Create or open a case, then import an EVTX folder.";
    public string StatusText { get => _statusText; set => SetProperty(ref _statusText, value); }

    private bool _isBusy;
    public bool IsBusy
    {
        get => _isBusy;
        set { if (SetProperty(ref _isBusy, value)) OnPropertyChanged(nameof(IsNotBusy)); }
    }
    public bool IsNotBusy => !_isBusy;

    private double _progressValue;
    public double ProgressValue { get => _progressValue; set => SetProperty(ref _progressValue, value); }

    private double _progressMax = 1;
    public double ProgressMax { get => _progressMax; set => SetProperty(ref _progressMax, value); }

    // ---- Analysis options ----

    public IReadOnlyList<TimeZoneInfo> TimeZones { get; }

    private TimeZoneInfo _selectedTimeZone;
    /// <summary>Zone the after-hours rule runs in (set it to the evidence site's zone). Re-runs analytics.</summary>
    public TimeZoneInfo SelectedTimeZone
    {
        get => _selectedTimeZone;
        set
        {
            if (value is null || !SetProperty(ref _selectedTimeZone, value)) return;
            if (_allEvents.Count > 0 && !IsBusy) { RecomputeAnalytics(); RefreshDashboard(); }
        }
    }

    private bool _useHostTimeZones = true;
    /// <summary>Evaluate after-hours in each host's own zone (System 6013); the selected zone is the fallback.</summary>
    public bool UseHostTimeZones
    {
        get => _useHostTimeZones;
        set
        {
            if (!SetProperty(ref _useHostTimeZones, value)) return;
            if (_allEvents.Count > 0 && !IsBusy) { RecomputeAnalytics(); RefreshDashboard(); }
        }
    }

    private bool _dropNoiseOnImport = true;
    /// <summary>Skip machine / system-account logon, logoff and ticket events while importing.</summary>
    public bool DropNoiseOnImport { get => _dropNoiseOnImport; set => SetProperty(ref _dropNoiseOnImport, value); }

    // ---- Filter inputs ----

    private string? _filterUser;
    public string? FilterUser { get => _filterUser; set => SetProperty(ref _filterUser, value); }
    private string? _filterHost;
    public string? FilterHost { get => _filterHost; set => SetProperty(ref _filterHost, value); }
    private string? _filterSourceIp;
    public string? FilterSourceIp { get => _filterSourceIp; set => SetProperty(ref _filterSourceIp, value); }
    private string? _filterEventId;
    public string? FilterEventId { get => _filterEventId; set => SetProperty(ref _filterEventId, value); }
    private string? _filterLogonType;
    public string? FilterLogonType { get => _filterLogonType; set => SetProperty(ref _filterLogonType, value); }
    private string? _filterAuthPackage;
    public string? FilterAuthPackage { get => _filterAuthPackage; set => SetProperty(ref _filterAuthPackage, value); }
    private string? _filterTechnique;
    public string? FilterTechnique { get => _filterTechnique; set => SetProperty(ref _filterTechnique, value); }
    private DateTime? _filterFrom;
    public DateTime? FilterFrom { get => _filterFrom; set => SetProperty(ref _filterFrom, value); }
    private DateTime? _filterTo;
    public DateTime? FilterTo { get => _filterTo; set => SetProperty(ref _filterTo, value); }

    // Optional time-of-day (UTC) for the date range (HH:mm or HH:mm:ss). Empty => whole day.
    private string? _filterFromTime;
    public string? FilterFromTime { get => _filterFromTime; set => SetProperty(ref _filterFromTime, value); }
    private string? _filterToTime;
    public string? FilterToTime { get => _filterToTime; set => SetProperty(ref _filterToTime, value); }

    private bool _successOnly;
    public bool SuccessOnly { get => _successOnly; set => SetProperty(ref _successOnly, value); }
    private bool _failureOnly;
    public bool FailureOnly { get => _failureOnly; set => SetProperty(ref _failureOnly, value); }
    private bool _privilegedOnly;
    public bool PrivilegedOnly { get => _privilegedOnly; set => SetProperty(ref _privilegedOnly, value); }
    private bool _rdpOnly;
    public bool RdpOnly { get => _rdpOnly; set => SetProperty(ref _rdpOnly, value); }
    private bool _remoteExecOnly;
    public bool RemoteExecOnly { get => _remoteExecOnly; set => SetProperty(ref _remoteExecOnly, value); }
    private bool _excludeMachineAccounts;
    public bool ExcludeMachineAccounts { get => _excludeMachineAccounts; set => SetProperty(ref _excludeMachineAccounts, value); }
    private bool _excludeLocalBlank;
    public bool ExcludeLocalBlank { get => _excludeLocalBlank; set => SetProperty(ref _excludeLocalBlank, value); }

    /// <summary>Suppresses auto-apply while several filter fields are reset at once.</summary>
    private bool _suppressApply;

    private bool _iocOnly;
    public bool IocOnly
    {
        get => _iocOnly;
        set { if (SetProperty(ref _iocOnly, value) && !_suppressApply) ApplyFilter(); }
    }

    // ---- IOC inputs ----

    private string? _iocHosts;
    public string? IocHosts { get => _iocHosts; set => SetProperty(ref _iocHosts, value); }
    private string? _iocIps;
    public string? IocIps { get => _iocIps; set => SetProperty(ref _iocIps, value); }
    private string? _iocUsers;
    public string? IocUsers { get => _iocUsers; set => SetProperty(ref _iocUsers, value); }

    public string IocSummary => _iocs.IsEmpty
        ? "No IOCs loaded. Paste hostnames, IPs and/or usernames above, then Apply."
        : $"{_iocs.HostCount} host(s), {_iocs.IpCount} IP(s), {_iocs.UserCount} user(s) loaded — " +
          $"{_allEvents.Count(e => e.IsIoc)} matching event(s), {_sessions.Count(s => s.IsIoc)} session(s) flagged.";

    // ---- Selection / detail ----

    private NormalizedEvent? _selectedEvent;
    public NormalizedEvent? SelectedEvent
    {
        get => _selectedEvent;
        set { if (SetProperty(ref _selectedEvent, value)) OnPropertyChanged(nameof(SelectedEventDetail)); }
    }

    private RemoteSession? _selectedSession;
    public RemoteSession? SelectedSession { get => _selectedSession; set => SetProperty(ref _selectedSession, value); }

    /// <summary>All populated fields of the selected event plus its original XML (loaded from the case on demand).</summary>
    public string SelectedEventDetail
    {
        get
        {
            var e = _selectedEvent;
            if (e is null) return "Select an event to see every field and the original event XML.";
            var sb = new StringBuilder();
            foreach (var col in CsvExporter.EventColumns)
            {
                var v = col.Value(e);
                if (!string.IsNullOrEmpty(v)) sb.Append(col.Header.PadRight(22)).Append(v).AppendLine();
            }
            string? xml = e.RawXml;
            if (xml is null && _store is not null && e.Id > 0)
            {
                try { xml = _store.GetRawXml(e.Id); } catch (Exception ex) { xml = $"(could not load raw XML: {ex.Message})"; }
            }
            sb.AppendLine().AppendLine("---- Original event XML ----").Append(PrettyXml(xml) ?? "(not stored)");
            return sb.ToString();
        }
    }

    private static string? PrettyXml(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try { return System.Xml.Linq.XDocument.Parse(xml).ToString(); } catch { return xml; }
    }

    public int StoryWindowMinutes { get; set; }

    // ---- Dashboard counters (track the current filtered view) ----

    public int TotalEvents => _view.Count;
    public int SuccessfulLogons => _view.Count(e => e.CountsAsLogonSuccess);
    public int FailedLogons => _view.Count(e => e.IsFailure);
    public int RdpLogons => _view.Count(e => e.EventId == 4624 && e.LogonType is 10 or 12);
    public int ExplicitCredentialUse => _view.Count(e => e.EventId == 4648);
    public int PrivilegedLogons => _view.Count(e => e.IsPrivileged);
    public int UniqueUsers => _view.Where(e => !string.IsNullOrWhiteSpace(e.TargetUserName))
        .Select(e => UserKey.Bare(e.TargetUserName)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int UniqueSourceIps => _view.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp))
        .Select(e => e.SourceIp!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int UniqueHosts => _view.Where(e => !string.IsNullOrWhiteSpace(e.Hostname))
        .Select(e => HostKey.Of(e.Hostname)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int SuspiciousCount => Findings.Count;
    public int HighFindings => Findings.Count(f => f.Severity >= FindingSeverity.High);
    public int RemoteExecSessions => _sessions.Count(s => s.Direction == "Inbound" && s.Technique != RemoteTechnique.Rdp);
    public int RdpSessions => _sessions.Count(s => s.Direction == "Inbound" && s.Technique == RemoteTechnique.Rdp);

    // ---- Commands ----

    private void NewCase()
    {
        var dlg = new SaveFileDialog
        {
            Title = "New or existing case database",
            Filter = "Triage case (*.latdb)|*.latdb|All files (*.*)|*.*",
            FileName = $"Case-{DateTime.Now:yyyyMMdd-HHmmss}.latdb",
            OverwritePrompt = false,
        };
        if (dlg.ShowDialog() != true) return;

        var name = Path.GetFileNameWithoutExtension(dlg.FileName);

        if (File.Exists(dlg.FileName))
        {
            var choice = MessageBox.Show(
                $"A case database already exists at:\n{dlg.FileName}\n\n" +
                "Yes  — open the existing case (restore its events & IOCs)\n" +
                "No   — overwrite it with a new, empty case\n" +
                "Cancel — do nothing",
                "Existing case database", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

            if (choice == MessageBoxResult.Cancel) return;
            if (choice == MessageBoxResult.Yes)
            {
                OpenStore(dlg.FileName, createCase: false, name);
                return;
            }

            _store?.Dispose();
            _store = null;
            try
            {
                foreach (var path in new[] { dlg.FileName, dlg.FileName + "-wal", dlg.FileName + "-shm" })
                    if (File.Exists(path)) File.Delete(path);
            }
            catch (IOException)
            {
                MessageBox.Show("Could not overwrite the database — it may be open in another program.",
                    "Overwrite failed", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        OpenStore(dlg.FileName, createCase: true, name);
        StatusText = $"Created case '{CaseName}' at {dlg.FileName}. Now import an EVTX folder.";
    }

    private void ImportFolder()
    {
        var folder = new OpenFolderDialog { Title = "Select folder containing EVTX files" };
        if (folder.ShowDialog() != true) return;

        var path = folder.FolderName;
        var discovered = EvtxImporter.DiscoverEvtxFiles(path);
        if (discovered.Count == 0)
        {
            MessageBox.Show("No .evtx files were found under the selected folder.",
                "Import", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (_store is null)
        {
            // No explicit case yet: create one in a visible folder next to the evidence's parent,
            // falling back to Documents, and say where it went.
            var caseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "LoginActivityTriage Cases");
            var dbPath = Path.Combine(caseDir, $"QuickTriage-{DateTime.Now:yyyyMMdd-HHmmss}.latdb");
            OpenStore(dbPath, createCase: true, "Quick Triage");
            ErrorLog.Add($"Quick-triage case created at {dbPath}");
        }

        RunImport(path, discovered.Count);
    }

    private void RunImport(string folder, int fileCount)
    {
        IsBusy = true;
        ProgressValue = 0;
        ProgressMax = fileCount;
        StatusText = $"Importing {fileCount} EVTX file(s)...";
        _importCts = new CancellationTokenSource();
        var ct = _importCts.Token;
        var store = _store!;
        var existing = _allEvents.Select(e => e.DedupeKey).ToHashSet(StringComparer.Ordinal);
        var context = _allEvents.Where(e => e.EventId == 4624).ToList();
        var dropNoise = DropNoiseOnImport;
        var imported = new List<NormalizedEvent>();

        var progress = new Progress<ImportProgress>(p =>
        {
            ProgressValue = p.FileIndex;
            StatusText = string.IsNullOrEmpty(p.CurrentFile)
                ? $"Finalising... {p.EventsNormalisedSoFar:N0} events"
                : $"[{p.FileIndex + 1}/{p.FileCount}] {Path.GetFileName(p.CurrentFile)} - {p.EventsNormalisedSoFar:N0} events";
        });

        Task.Run(() =>
        {
            var buffer = new List<NormalizedEvent>();
            var candidates = new List<NormalizedEvent>();

            void Flush()
            {
                if (buffer.Count == 0) return;
                store.InsertEvents(buffer, dropRawXmlAfterInsert: true);
                imported.AddRange(buffer.Where(e => e.Id != 0));
                buffer.Clear();
            }

            var options = new ImportOptions
            {
                ExistingKeys = existing,
                Keep = dropNoise ? e => !NoiseFilter.IsRoutineNoise(e) : null,
            };

            ImportSummary? summary = null;
            try
            {
                summary = new EvtxImporter().Import(folder, e =>
                {
                    if (e.KeepOnlyIfLinked) candidates.Add(e);
                    else
                    {
                        buffer.Add(e);
                        if (buffer.Count >= 5000) Flush();
                    }
                }, progress, ct, options);
            }
            catch (OperationCanceledException)
            {
                // keep what was read so far
            }
            Flush();
            buffer.AddRange(ProcessEventFilter.Apply(candidates, imported.Concat(context)));
            Flush();
            if (summary is not null)
                foreach (var f in summary.Files) store.RecordImportedFile(f);
            return summary;
        }).ContinueWith(t =>
        {
            try
            {
                if (t.IsFaulted)
                {
                    StatusText = "Import failed.";
                    ErrorLog.Add(t.Exception?.GetBaseException().Message ?? "Unknown import error");
                    return;
                }

                var summary = t.Result;
                _allEvents.AddRange(imported);
                if (summary is not null) foreach (var err in summary.Errors) ErrorLog.Add(err);

                RecomputeAnalytics();
                ApplyIocFlags();
                ApplyFilter();

                StatusText = summary is null
                    ? $"Import cancelled - {imported.Count:N0} event(s) imported before stopping."
                    : $"Imported {imported.Count:N0} events from {summary.FilesProcessed} file(s); " +
                      $"{summary.TotalDuplicates:N0} duplicate(s) and {summary.TotalFiltered:N0} noise event(s) skipped, " +
                      $"{summary.TotalSkipped:N0} unreadable record(s), {summary.FilesFailed} file(s) failed.";
            }
            finally
            {
                IsBusy = false;
                _importCts?.Dispose();
                _importCts = null;
            }
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    private void OpenStore(string dbPath, bool createCase, string caseName)
    {
        _store?.Dispose();
        _allEvents.Clear();
        _sessions = new();
        _view = new();
        Events.ReplaceAll(Array.Empty<NormalizedEvent>());
        Findings.ReplaceAll(Array.Empty<Finding>());
        RemoteSessions.ReplaceAll(Array.Empty<RemoteSession>());
        ErrorLog.Clear();

        _suppressApply = true;
        ClearFilterFieldsOnly();
        IocHosts = IocIps = IocUsers = null;
        _iocs.Clear();
        _suppressApply = false;

        _store = CaseStore.Open(dbPath);

        if (createCase)
        {
            _store.CreateCase(caseName);
            CaseName = caseName;
            RefreshDashboard();
            return;
        }

        // Reopen an existing case: restore events and IOCs; analytics are recomputed so
        // sessions and findings always reflect the current rule set.
        var info = _store.LoadLatestCase();
        CaseName = info?.Name ?? caseName;
        _allEvents.AddRange(_store.QueryEvents());

        var (h, i, u) = _store.LoadIocs();
        IocHosts = h; IocIps = i; IocUsers = u;
        _iocs.Set(h, i, u);

        RecomputeAnalytics();
        ApplyIocFlags();
        OnPropertyChanged(nameof(IocSummary));
        ApplyFilter();
        StatusText = $"Opened case '{CaseName}' — {_allEvents.Count:N0} event(s), {_sessions.Count:N0} remote session(s), " +
                     $"{Findings.Count} finding(s).";
    }

    private EventFilter BuildFilter()
    {
        int? eid = int.TryParse(FilterEventId, out var e) ? e : null;
        int? lt = int.TryParse(FilterLogonType, out var l) ? l : null;
        return new EventFilter
        {
            From = CombineDateAndTime(FilterFrom, FilterFromTime, endOfDayIfNoTime: false),
            To = CombineDateAndTime(FilterTo, FilterToTime, endOfDayIfNoTime: true),
            EventId = eid,
            User = FilterUser,
            Host = FilterHost,
            SourceIp = FilterSourceIp,
            LogonType = lt,
            AuthPackage = FilterAuthPackage,
            Technique = FilterTechnique,
            Success = SuccessOnly ? true : (FailureOnly ? false : (bool?)null),
            PrivilegedOnly = PrivilegedOnly,
            RdpOnly = RdpOnly,
            RemoteExecOnly = RemoteExecOnly,
            ExcludeMachineAccounts = ExcludeMachineAccounts,
            ExcludeLocalOrBlankSource = ExcludeLocalBlank,
        };
    }

    /// <summary>
    /// Combines a picked date with an optional time-of-day as a UTC bound (the grid shows UTC).
    /// Without a time the bound is the start of the day or, for the upper bound, its last tick.
    /// </summary>
    private static DateTimeOffset? CombineDateAndTime(DateTime? date, string? time, bool endOfDayIfNoTime)
    {
        if (date is null) return null;
        var day = date.Value.Date;
        if (!string.IsNullOrWhiteSpace(time) &&
            TimeSpan.TryParse(time.Trim(), CultureInfo.InvariantCulture, out var ts))
            return new DateTimeOffset(day + ts, TimeSpan.Zero);
        return new DateTimeOffset(endOfDayIfNoTime ? day.AddDays(1).AddTicks(-1) : day, TimeSpan.Zero);
    }

    private void ApplyFilter()
    {
        var filter = BuildFilter();
        IEnumerable<NormalizedEvent> q = _allEvents.Where(filter.Matches);
        if (IocOnly) q = q.Where(e => e.IsIoc);
        _view = q.ToList();

        Events.ReplaceAll(_view);
        RemoteSessions.ReplaceAll(IocOnly ? _sessions.Where(s => s.IsIoc) : _sessions);
        RefreshDashboard();

        StatusText = $"Showing {_view.Count:N0} of {_allEvents.Count:N0} events" +
                     (IocOnly ? " (IOC matches only)." : ".");
    }

    private void ClearFilter()
    {
        _suppressApply = true;
        ClearFilterFieldsOnly();
        _suppressApply = false;
        ApplyFilter();
    }

    private void ApplyQuickFilter(string? key)
    {
        _suppressApply = true;
        ClearFilterFieldsOnly();
        switch (key)
        {
            case "RDP": RdpOnly = true; break;
            case "Privileged": PrivilegedOnly = true; break;
            case "Explicit": FilterEventId = "4648"; break;
            case "NTLM": FilterAuthPackage = "NTLM"; break;
            case "KerberosFail": FilterEventId = "4771"; break;
            case "ServiceInstalled": FilterEventId = "7045"; break;
            case "AccountCreated": FilterEventId = "4720"; break;
            case "LogonType3": FilterLogonType = "3"; break;
            case "LogonType10": FilterLogonType = "10"; break;
            case "ExcludeMachine": ExcludeMachineAccounts = true; break;
            case "Failures": FailureOnly = true; break;
            case "RemoteExec": RemoteExecOnly = true; break;
            case "PsExec": FilterTechnique = RemoteTechnique.PsExec; break;
            case "PsRemoting": FilterTechnique = RemoteTechnique.PsRemoting; break;
            case "LogCleared": FilterTechnique = RemoteTechnique.LogCleared; break;
            case "Iocs": IocOnly = true; break;
        }
        _suppressApply = false;
        ApplyFilter();
    }

    private void ClearFilterFieldsOnly()
    {
        FilterUser = FilterHost = FilterSourceIp = FilterEventId = FilterLogonType = FilterAuthPackage = FilterTechnique = null;
        FilterFrom = FilterTo = null;
        FilterFromTime = FilterToTime = null;
        SuccessOnly = FailureOnly = PrivilegedOnly = RdpOnly = RemoteExecOnly = ExcludeMachineAccounts = ExcludeLocalBlank = false;
        IocOnly = false;
    }

    // ---- IOCs ----

    private void ApplyIocs()
    {
        _iocs.Set(IocHosts, IocIps, IocUsers);
        ApplyIocFlags();
        _store?.SaveIocs(IocHosts, IocIps, IocUsers);
        OnPropertyChanged(nameof(IocSummary));
        ApplyFilter();
    }

    private void ClearIocs()
    {
        _suppressApply = true;
        IocHosts = IocIps = IocUsers = null;
        _iocs.Clear();
        IocOnly = false;
        _suppressApply = false;
        ApplyIocFlags();
        _store?.SaveIocs(null, null, null);
        OnPropertyChanged(nameof(IocSummary));
        ApplyFilter();
    }

    private void ApplyIocFlags()
    {
        foreach (var e in _allEvents) e.IsIoc = _iocs.Matches(e);
        foreach (var s in _sessions) s.IsIoc = _iocs.Matches(s) || s.Events.Any(e => e.IsIoc);
    }

    // ---- Export ----

    private void ExportCsv()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export current view to CSV",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"LogonTimeline-{DateTime.UtcNow:yyyyMMdd-HHmmss}Z.csv",
        };
        if (dlg.ShowDialog() != true) return;
        CsvExporter.Export(Events, dlg.FileName);
        StatusText = $"Exported {Events.Count:N0} rows to {dlg.FileName}";
    }

    private void ExportHtml()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export current view to HTML",
            Filter = "HTML file (*.html)|*.html",
            FileName = $"LogonTimeline-{DateTime.UtcNow:yyyyMMdd-HHmmss}Z.html",
        };
        if (dlg.ShowDialog() != true) return;
        HtmlExporter.ExportEvents(Events, dlg.FileName, $"Logon Timeline - {CaseName}");
        StatusText = $"Exported {Events.Count:N0} rows to {dlg.FileName}";
    }

    /// <summary>Findings + remote sessions as HTML and CSV, for the case notes.</summary>
    private void ExportReport()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export findings and remote sessions",
            Filter = "HTML report (*.html)|*.html",
            FileName = $"{CaseName}-Findings-{DateTime.UtcNow:yyyyMMdd-HHmmss}Z.html",
        };
        if (dlg.ShowDialog() != true) return;
        var baseName = Path.Combine(Path.GetDirectoryName(dlg.FileName)!, Path.GetFileNameWithoutExtension(dlg.FileName));
        HtmlExporter.ExportFindings(Findings, dlg.FileName, $"Findings - {CaseName}");
        HtmlExporter.ExportSessions(RemoteSessions, baseName + "-sessions.html", $"Remote sessions - {CaseName}");
        CsvExporter.Write(baseName + "-findings.csv", Findings, CsvExporter.FindingColumns);
        CsvExporter.Write(baseName + "-sessions.csv", RemoteSessions, CsvExporter.SessionColumns);
        StatusText = $"Exported {Findings.Count} finding(s) and {RemoteSessions.Count} session(s) next to {dlg.FileName}";
    }

    // ---- Stories ----

    private void ShowLogonStory(object? parameter)
    {
        var anchor = parameter as NormalizedEvent ?? SelectedEvent;
        if (anchor is null)
        {
            MessageBox.Show("Select an event first to build its Logon Story.",
                "Logon Story", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        LogonStoryRequested?.Invoke(LogonStoryViewModel.BuildForEvent(anchor, _allEvents, StoryWindowMinutes));
    }

    private void ShowSessionEvents(object? parameter)
    {
        var s = parameter as RemoteSession ?? SelectedSession;
        if (s is null)
        {
            MessageBox.Show("Select a remote session first.", "Remote session", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        LogonStoryRequested?.Invoke(LogonStoryViewModel.BuildForSession(s));
    }

    // ---- Analytics / dashboard ----

    private void RecomputeAnalytics()
    {
        var analyzer = new SuspiciousSequenceAnalyzer(new AnalyzerOptions { TimeZone = SelectedTimeZone, UseHostTimeZones = UseHostTimeZones });
        foreach (var e in _allEvents) e.RemoteSessionRef = null;
        var result = analyzer.Run(_allEvents);
        _sessions = result.Sessions;
        foreach (var s in _sessions) s.IsIoc = _iocs.Matches(s);
        Findings.ReplaceAll(result.Findings);
        RemoteSessions.ReplaceAll(_sessions);
        try { _store?.ReplaceFindings(result.Findings); }
        catch (Exception ex) { ErrorLog.Add("Could not store findings: " + ex.Message); }
        OnPropertyChanged(nameof(IocSummary));
    }

    private void RefreshDashboard()
    {
        foreach (var name in new[]
                 {
                     nameof(TotalEvents), nameof(SuccessfulLogons), nameof(FailedLogons),
                     nameof(RdpLogons), nameof(ExplicitCredentialUse), nameof(PrivilegedLogons),
                     nameof(UniqueUsers), nameof(UniqueSourceIps), nameof(UniqueHosts),
                     nameof(SuspiciousCount), nameof(HighFindings), nameof(RemoteExecSessions),
                     nameof(RdpSessions), nameof(CaseName),
                 })
            OnPropertyChanged(name);

        Fill(TopUsersSuccess, _view.Where(e => e.CountsAsLogonSuccess && !e.IsNoiseAccount && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => UserKey.Bare(e.TargetUserName));
        Fill(TopUsersFailed, _view.Where(e => e.IsFailure && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => UserKey.Bare(e.TargetUserName));
        Fill(TopSourceIps, _view.Where(e => !IpUtil.IsLocalOrBlank(e.SourceIp)), e => e.SourceIp!);
        Fill(TopHosts, _view.Where(e => !string.IsNullOrWhiteSpace(e.Hostname)), e => HostKey.Of(e.Hostname));
        Fill(TopPrivilegedUsers, _view.Where(e => e.IsPrivileged && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => UserKey.Bare(e.TargetUserName));
        Fill(TopRdpSourceIps, _view.Where(e => e.IsInboundRdp && !IpUtil.IsLocalOrBlank(e.SourceIp)), e => e.SourceIp!);

        RdpEvents.ReplaceAll(_view.Where(e => e.IsRdp));
        FailedEvents.ReplaceAll(_view.Where(e => e.IsFailure));
        AdminEvents.ReplaceAll(_view.Where(e => e.IsPrivileged || e.EventId == 4648));
        SourceIpPivots.ReplaceAll(PivotBuilder.BySourceIp(_view, _iocs));
        UserPivots.ReplaceAll(PivotBuilder.ByUser(_view, _iocs));
        HostPivots.ReplaceAll(PivotBuilder.ByHost(_view, _iocs));
    }

    private static void Fill(RangeObservableCollection<StatItem> target,
        IEnumerable<NormalizedEvent> source, Func<NormalizedEvent, string> key) =>
        target.ReplaceAll(source.GroupBy(key, StringComparer.OrdinalIgnoreCase)
            .Select(g => new StatItem(g.Key, g.Count()))
            .OrderByDescending(s => s.Count)
            .Take(10));
}
