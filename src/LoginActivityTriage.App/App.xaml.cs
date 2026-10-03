using System.Windows;
using System.Windows.Threading;

namespace LoginActivityTriage.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Never let an unhandled exception silently take down the investigator's session.
        DispatcherUnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            args.SetObserved();
            Dispatcher.BeginInvoke(() => Report(args.Exception.GetBaseException()));
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex) Report(ex);
        };
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Report(e.Exception);
        e.Handled = true;
    }

    private static void Report(Exception ex) =>
        MessageBox.Show(
            "An unexpected error occurred:\n\n" + ex.Message,
            "Login Activity Triage",
            MessageBoxButton.OK, MessageBoxImage.Error);
}
