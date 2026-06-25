using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using LoginActivityTriage.Analytics;
using LoginActivityTriage.App.Mvvm;
using LoginActivityTriage.Core.Models;
using LoginActivityTriage.Export;
using LoginActivityTriage.Parsing;
using LoginActivityTriage.Storage;
using Microsoft.Win32;

namespace LoginActivityTriage.App.ViewModels;

/// <summary>
/// Root view model: owns the open case, the in-memory event set, the timeline
/// filter, the dashboard projections and all top-level commands.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private readonly List<NormalizedEvent> _allEvents = new();

    /// <summary>The current filtered/IOC-restricted subset that feeds every view
    /// (timeline, RDP, failed, admin, pivots and the dashboard counters).</summary>
    private List<NormalizedEvent> _view = new();

    /// <summary>Investigator-supplied indicators; drives row highlighting and the
    /// "IOC matches only" filter across all views.</summary>
    private readonly IocSet _iocs = new();

    private CaseStore? _store;

    public ObservableCollection<NormalizedEvent> Events { get; } = new();
    public ObservableCollection<Finding> Findings { get; } = new();
    public ObservableCollection<string> ErrorLog { get; } = new();

    public ObservableCollection<StatItem> TopUsersSuccess { get; } = new();
    public ObservableCollection<StatItem> TopUsersFailed { get; } = new();
    public ObservableCollection<StatItem> TopSourceIps { get; } = new();
    public ObservableCollection<StatItem> TopHosts { get; } = new();
    public ObservableCollection<StatItem> TopPrivilegedUsers { get; } = new();
    public ObservableCollection<StatItem> TopRdpSourceIps { get; } = new();

    // Dedicated-tab subsets and pivots, all derived from the full event set.
    public ObservableCollection<NormalizedEvent> RdpEvents { get; } = new();
    public ObservableCollection<NormalizedEvent> FailedEvents { get; } = new();
    public ObservableCollection<NormalizedEvent> AdminEvents { get; } = new();
    public ObservableCollection<SourceIpPivot> SourceIpPivots { get; } = new();
    public ObservableCollection<UserPivot> UserPivots { get; } = new();
    public ObservableCollection<HostPivot> HostPivots { get; } = new();

    /// <summary>Raised when a Logon Story should be shown; the view opens the window.</summary>
    public event Action<LogonStoryViewModel>? LogonStoryRequested;

    public MainViewModel()
    {
        NewCaseCommand = new RelayCommand(NewCase);
        ImportFolderCommand = new RelayCommand(ImportFolder, () => !IsBusy);
        ApplyFilterCommand = new RelayCommand(ApplyFilter);
        ClearFilterCommand = new RelayCommand(ClearFilter);
        ExportCsvCommand = new RelayCommand(ExportCsv, () => Events.Count > 0);
        ExportHtmlCommand = new RelayCommand(ExportHtml, () => Events.Count > 0);
        ShowLogonStoryCommand = new RelayCommand(ShowLogonStory);
        QuickFilterCommand = new RelayCommand(p => ApplyQuickFilter(p as string));
        ApplyIocsCommand = new RelayCommand(ApplyIocs);
        ClearIocsCommand = new RelayCommand(ClearIocs);
        StoryWindowMinutes = 30;
    }

    public RelayCommand NewCaseCommand { get; }
    public RelayCommand ImportFolderCommand { get; }
    public RelayCommand ApplyFilterCommand { get; }
    public RelayCommand ClearFilterCommand { get; }
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ShowLogonStoryCommand { get; }
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
    private DateTime? _filterFrom;
    public DateTime? FilterFrom { get => _filterFrom; set => SetProperty(ref _filterFrom, value); }
    private DateTime? _filterTo;
    public DateTime? FilterTo { get => _filterTo; set => SetProperty(ref _filterTo, value); }

    // Optional time-of-day for the date range (HH:mm or HH:mm:ss). Empty => whole day.
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
    private bool _excludeMachineAccounts;
    public bool ExcludeMachineAccounts { get => _excludeMachineAccounts; set => SetProperty(ref _excludeMachineAccounts, value); }
    private bool _excludeLocalBlank;
    public bool ExcludeLocalBlank { get => _excludeLocalBlank; set => SetProperty(ref _excludeLocalBlank, value); }

    /// <summary>Suppresses auto-apply while several filter fields are reset at once.</summary>
    private bool _suppressApply;

    /// <summary>When set, every view is restricted to events that match a loaded IOC.
    /// Toggling re-applies immediately (no need to click Apply Filter).</summary>
    private bool _iocOnly;
    public bool IocOnly
    {
        get => _iocOnly;
        set { if (SetProperty(ref _iocOnly, value) && !_suppressApply) ApplyFilter(); }
    }

    // ---- IOC inputs (pasted indicator lists) ----

    private string? _iocHosts;
    public string? IocHosts { get => _iocHosts; set => SetProperty(ref _iocHosts, value); }
    private string? _iocIps;
    public string? IocIps { get => _iocIps; set => SetProperty(ref _iocIps, value); }
    private string? _iocUsers;
    public string? IocUsers { get => _iocUsers; set => SetProperty(ref _iocUsers, value); }

    /// <summary>Human-readable summary of the loaded IOCs and how many events match.</summary>
    public string IocSummary => _iocs.IsEmpty
        ? "No IOCs loaded. Paste hostnames, IPs and/or usernames above, then Apply."
        : $"{_iocs.HostCount} host(s), {_iocs.IpCount} IP(s), {_iocs.UserCount} user(s) loaded — " +
          $"{_allEvents.Count(e => e.IsIoc)} matching event(s) flagged.";

    private NormalizedEvent? _selectedEvent;
    public NormalizedEvent? SelectedEvent { get => _selectedEvent; set => SetProperty(ref _selectedEvent, value); }

    public int StoryWindowMinutes { get; set; }

    // ---- Dashboard counters ----

    // Counters reflect the current filtered view so the dashboard tracks any active filter.
    public int TotalEvents => _view.Count;
    public int SuccessfulLogons => _view.Count(e => e.EventId == 4624);
    public int FailedLogons => _view.Count(e => e.EventId == 4625);
    public int RdpLogons => _view.Count(e => e.IsRdp);
    public int ExplicitCredentialUse => _view.Count(e => e.EventId == 4648);
    public int PrivilegedLogons => _view.Count(e => e.IsPrivileged);
    public int UniqueUsers => _view.Where(e => !string.IsNullOrWhiteSpace(e.TargetUserName))
        .Select(e => e.TargetUserName!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int UniqueSourceIps => _view.Where(e => !string.IsNullOrWhiteSpace(e.SourceIp))
        .Select(e => e.SourceIp!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int UniqueHosts => _view.Where(e => !string.IsNullOrWhiteSpace(e.Hostname))
        .Select(e => e.Hostname!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
    public int SuspiciousCount => Findings.Count;

    // ---- Commands ----

    private void NewCase()
    {
        var dlg = new SaveFileDialog
        {
            Title = "New or existing case database",
            Filter = "Triage case (*.latdb)|*.latdb|All files (*.*)|*.*",
            FileName = $"Case-{DateTime.Now:yyyyMMdd-HHmmss}.latdb",
            OverwritePrompt = false,   // we present our own use/overwrite choice below
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

            // Overwrite: dispose any open handle (also clears the SQLite pool) and
            // remove the db plus its WAL/SHM sidecars.
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
        StatusText = $"Created case '{CaseName}'. Now import an EVTX folder.";
    }

    private void ImportFolder()
    {
        if (_store is null)
        {
            // No explicit case yet: spin up a quick-triage case under TEMP.
            var temp = Path.Combine(Path.GetTempPath(),
                $"LoginTriage-{DateTime.Now:yyyyMMdd-HHmmss}.latdb");
            OpenStore(temp, createCase: true, "Quick Triage");
        }

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

        RunImport(path, discovered.Count);
    }

    private void RunImport(string folder, int fileCount)
    {
        IsBusy = true;
        ProgressValue = 0;
        ProgressMax = fileCount;
        StatusText = $"Importing {fileCount} EVTX file(s)...";

        var batch = new List<NormalizedEvent>();
        var progress = new Progress<ImportProgress>(p =>
        {
            ProgressValue = p.FileIndex;
            StatusText = string.IsNullOrEmpty(p.CurrentFile)
                ? $"Finalising... {p.EventsNormalisedSoFar} events"
                : $"[{p.FileIndex + 1}/{p.FileCount}] {Path.GetFileName(p.CurrentFile)} - {p.EventsNormalisedSoFar} events";
        });

        Task.Run(() =>
        {
            var importer = new EvtxImporter();
            var summary = importer.Import(folder, e => batch.Add(e), progress);
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
                // Persist to SQLite (assigns row ids) and record per-file outcomes.
                _store!.InsertEvents(batch);
                foreach (var f in summary.Files)
                    _store!.RecordImportedFile(f);

                _allEvents.AddRange(batch);
                foreach (var err in summary.Errors) ErrorLog.Add(err);

                RecomputeAnalytics();
                ApplyIocFlags();   // flag any events matching already-loaded IOCs
                ApplyFilter();     // builds _view and refreshes every view + dashboard

                StatusText = $"Imported {summary.TotalEventsNormalised} events from " +
                             $"{summary.FilesProcessed} file(s); {summary.TotalSkipped} record(s) skipped, " +
                             $"{summary.FilesFailed} file(s) failed.";
            }
            finally
            {
                IsBusy = false;
            }
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    private void OpenStore(string dbPath, bool createCase, string caseName)
    {
        _store?.Dispose();
        _allEvents.Clear();
        _view = new();
        Events.Clear();
        Findings.Clear();
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

        // Reopen an existing case: restore its events, findings and IOCs.
        var info = _store.LoadLatestCase();
        CaseName = info?.Name ?? caseName;

        _allEvents.AddRange(_store.QueryEvents());
        foreach (var f in _store.QueryFindings()) Findings.Add(f);

        var (h, i, u) = _store.LoadIocs();
        IocHosts = h; IocIps = i; IocUsers = u;
        _iocs.Set(h, i, u);
        ApplyIocFlags();
        OnPropertyChanged(nameof(IocSummary));

        ApplyFilter();
        StatusText = $"Opened case '{CaseName}' — {_allEvents.Count} event(s), " +
                     $"{Findings.Count} finding(s) restored.";
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
            Success = SuccessOnly ? true : (FailureOnly ? false : (bool?)null),
            PrivilegedOnly = PrivilegedOnly,
            RdpOnly = RdpOnly,
            ExcludeMachineAccounts = ExcludeMachineAccounts,
            ExcludeLocalOrBlankSource = ExcludeLocalBlank,
        };
    }

    /// <summary>
    /// Combines a picked date with an optional time-of-day string. When no time is
    /// given the bound is the start of the day, or (for the upper bound) the last
    /// tick of the day so the whole "To" date is inclusive.
    /// </summary>
    private static DateTimeOffset? CombineDateAndTime(DateTime? date, string? time, bool endOfDayIfNoTime)
    {
        if (date is null) return null;
        var day = date.Value.Date;
        if (!string.IsNullOrWhiteSpace(time) &&
            TimeSpan.TryParse(time.Trim(), System.Globalization.CultureInfo.InvariantCulture, out var ts))
            return new DateTimeOffset(day + ts);
        return new DateTimeOffset(endOfDayIfNoTime ? day.AddDays(1).AddTicks(-1) : day);
    }

    /// <summary>
    /// Rebuilds the shared filtered view from the field filter (and the optional
    /// "IOC matches only" toggle) and refreshes EVERY downstream view: the timeline,
    /// the RDP / failed / admin subsets, the pivots and the dashboard counters.
    /// </summary>
    private void ApplyFilter()
    {
        var filter = BuildFilter();
        IEnumerable<NormalizedEvent> q = _allEvents.Where(filter.Matches);
        if (IocOnly) q = q.Where(e => e.IsIoc);
        _view = q.ToList();

        Events.Clear();
        foreach (var e in _view) Events.Add(e);

        RefreshDashboard();   // counters, top-lists and derived views all read _view

        StatusText = $"Showing {_view.Count} of {_allEvents.Count} events" +
                     (IocOnly ? " (IOC matches only)." : ".");
    }

    private void ClearFilter()
    {
        _suppressApply = true;
        ClearFilterFieldsOnly();
        _suppressApply = false;
        ApplyFilter();
    }

    /// <summary>Applies one of the section-8 defensive quick filters.</summary>
    private void ApplyQuickFilter(string? key)
    {
        _suppressApply = true;
        ClearFilterFieldsOnly();
        switch (key)
        {
            case "RDP": RdpOnly = true; break;
            case "FailedThenSuccess": FailureOnly = true; break; // narrows view; Findings tab has the correlation
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
            case "Iocs": IocOnly = true; break;
        }
        _suppressApply = false;
        ApplyFilter();
    }

    private void ClearFilterFieldsOnly()
    {
        FilterUser = FilterHost = FilterSourceIp = FilterEventId = FilterLogonType = FilterAuthPackage = null;
        FilterFrom = FilterTo = null;
        FilterFromTime = FilterToTime = null;
        SuccessOnly = FailureOnly = PrivilegedOnly = RdpOnly = ExcludeMachineAccounts = ExcludeLocalBlank = false;
        IocOnly = false;
    }

    // ---- IOCs ----

    /// <summary>Parses the pasted indicator lists, flags matching events and refreshes views.</summary>
    private void ApplyIocs()
    {
        _iocs.Set(IocHosts, IocIps, IocUsers);
        ApplyIocFlags();
        _store?.SaveIocs(IocHosts, IocIps, IocUsers);   // persist with the case
        OnPropertyChanged(nameof(IocSummary));
        ApplyFilter();   // repaint highlights + recompute pivots against the new IOCs
    }

    /// <summary>Clears all loaded indicators and the IOC-only filter.</summary>
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

    /// <summary>(Re)computes the per-event IOC flag used for row highlighting.</summary>
    private void ApplyIocFlags()
    {
        foreach (var e in _allEvents) e.IsIoc = _iocs.Matches(e);
    }

    private void ExportCsv()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export current view to CSV",
            Filter = "CSV file (*.csv)|*.csv",
            FileName = $"LogonTimeline-{DateTime.Now:yyyyMMdd-HHmmss}.csv",
        };
        if (dlg.ShowDialog() != true) return;
        CsvExporter.Export(Events, dlg.FileName);
        StatusText = $"Exported {Events.Count} rows to {dlg.FileName}";
    }

    private void ExportHtml()
    {
        var dlg = new SaveFileDialog
        {
            Title = "Export current view to HTML",
            Filter = "HTML file (*.html)|*.html",
            FileName = $"LogonTimeline-{DateTime.Now:yyyyMMdd-HHmmss}.html",
        };
        if (dlg.ShowDialog() != true) return;
        HtmlExporter.ExportEvents(Events, dlg.FileName, $"Logon Timeline - {CaseName}");
        StatusText = $"Exported {Events.Count} rows to {dlg.FileName}";
    }

    private void ShowLogonStory(object? parameter)
    {
        var anchor = parameter as NormalizedEvent ?? SelectedEvent;
        if (anchor is null)
        {
            MessageBox.Show("Select an event first to build its Logon Story.",
                "Logon Story", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var story = LogonStoryViewModel.BuildForEvent(anchor, _allEvents, StoryWindowMinutes);
        LogonStoryRequested?.Invoke(story);
    }

    private void RecomputeAnalytics()
    {
        Findings.Clear();
        var analyzer = new SuspiciousSequenceAnalyzer();
        foreach (var f in analyzer.Analyze(_allEvents).OrderByDescending(x => x.Severity).ThenBy(x => x.Timestamp))
        {
            Findings.Add(f);
            _store?.InsertFinding(f);
        }
    }

    private void RefreshDashboard()
    {
        foreach (var name in new[]
                 {
                     nameof(TotalEvents), nameof(SuccessfulLogons), nameof(FailedLogons),
                     nameof(RdpLogons), nameof(ExplicitCredentialUse), nameof(PrivilegedLogons),
                     nameof(UniqueUsers), nameof(UniqueSourceIps), nameof(UniqueHosts),
                     nameof(SuspiciousCount), nameof(CaseName),
                 })
            OnPropertyChanged(name);

        Fill(TopUsersSuccess, _view.Where(e => e.EventId == 4624 && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => e.TargetUserName!);
        Fill(TopUsersFailed, _view.Where(e => e.EventId == 4625 && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => e.TargetUserName!);
        Fill(TopSourceIps, _view.Where(e => !string.IsNullOrWhiteSpace(e.SourceIp)), e => e.SourceIp!);
        Fill(TopHosts, _view.Where(e => !string.IsNullOrWhiteSpace(e.Hostname)), e => e.Hostname!);
        Fill(TopPrivilegedUsers, _view.Where(e => e.IsPrivileged && !string.IsNullOrWhiteSpace(e.TargetUserName)), e => e.TargetUserName!);
        Fill(TopRdpSourceIps, _view.Where(e => e.IsRdp && !string.IsNullOrWhiteSpace(e.SourceIp)), e => e.SourceIp!);

        RefreshDerivedViews();
    }

    /// <summary>Rebuilds the dedicated-tab subsets and the pivot grids from the full event set.</summary>
    private void RefreshDerivedViews()
    {
        Replace(RdpEvents, _view.Where(e => e.IsRdp));
        Replace(FailedEvents, _view.Where(e => e.IsFailure));
        // Admin usage: privileged sessions, elevated logons and explicit-credential use.
        Replace(AdminEvents, _view.Where(e => e.IsPrivileged || e.EventId == 4648));
        Replace(SourceIpPivots, PivotBuilder.BySourceIp(_view, _iocs));
        Replace(UserPivots, PivotBuilder.ByUser(_view, _iocs));
        Replace(HostPivots, PivotBuilder.ByHost(_view, _iocs));
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> source)
    {
        target.Clear();
        foreach (var item in source) target.Add(item);
    }

    private static void Fill(ObservableCollection<StatItem> target,
        IEnumerable<NormalizedEvent> source, Func<NormalizedEvent, string> key)
    {
        target.Clear();
        foreach (var g in source.GroupBy(key, StringComparer.OrdinalIgnoreCase)
                     .Select(g => new StatItem(g.Key, g.Count()))
                     .OrderByDescending(s => s.Count)
                     .Take(10))
            target.Add(g);
    }
}
