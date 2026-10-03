using System.Windows;
using System.Windows.Input;
using LoginActivityTriage.App.ViewModels;

namespace LoginActivityTriage.App.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm = new();

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        _vm.LogonStoryRequested += OnLogonStoryRequested;
    }

    private void OnLogonStoryRequested(LogonStoryViewModel story)
    {
        var window = new LogonStoryWindow(story) { Owner = this };
        window.Show();
    }

    private void SessionsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (_vm.SelectedSession is not null) _vm.ShowSessionEventsCommand.Execute(_vm.SelectedSession);
    }
}
