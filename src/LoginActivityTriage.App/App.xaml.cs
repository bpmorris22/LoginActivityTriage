using System.Windows;
using System.Windows.Threading;

namespace LoginActivityTriage.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Never let an unhandled exception take down the investigator's session.
        DispatcherUnhandledException += OnUnhandledException;
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            "An unexpected error occurred:\n\n" + e.Exception.Message,
            "Login Activity Triage",
            MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
