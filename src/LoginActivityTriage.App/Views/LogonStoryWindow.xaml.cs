using System.Windows;
using LoginActivityTriage.App.ViewModels;

namespace LoginActivityTriage.App.Views;

public partial class LogonStoryWindow : Window
{
    public LogonStoryWindow(LogonStoryViewModel story)
    {
        InitializeComponent();
        DataContext = story;
    }
}
