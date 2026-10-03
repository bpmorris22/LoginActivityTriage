using LoginActivityTriage.App.ViewModels;
using LoginActivityTriage.App.Views;
using LoginActivityTriage.Core.Models;
using Xunit;

namespace LoginActivityTriage.Tests;

/// <summary>
/// Loads the WPF windows' XAML (without showing them) so markup errors - missing resources,
/// bad converters, malformed bindings syntax - fail the build instead of the analyst's session.
/// </summary>
public class WpfSmokeTests
{
    private static void OnSta(Action action)
    {
        Exception? error = null;
        var t = new Thread(() =>
        {
            try { action(); }
            catch (Exception ex) { error = ex; }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null) throw new Xunit.Sdk.XunitException("WPF load failed: " + error);
    }

    [Fact]
    public void MainAndStoryWindows_LoadTheirXaml()
    {
        OnSta(() =>
        {
            var app = System.Windows.Application.Current as LoginActivityTriage.App.App ?? new LoginActivityTriage.App.App();
            app.InitializeComponent();   // app-level resources (brushes, converters, styles)

            var main = new MainWindow();
            Assert.IsType<MainViewModel>(main.DataContext);

            var session = new RemoteSession { Id = 1, Technique = "PsExec", Host = "SRV01", Start = DateTimeOffset.UtcNow, End = DateTimeOffset.UtcNow };
            session.Events.Add(new NormalizedEvent { EventId = 7045, Hostname = "SRV01", Timestamp = DateTimeOffset.UtcNow });
            var story = new LogonStoryWindow(LogonStoryViewModel.BuildForSession(session));
            Assert.NotNull(story.Content);
            main.Close();
            story.Close();
        });
    }
}
