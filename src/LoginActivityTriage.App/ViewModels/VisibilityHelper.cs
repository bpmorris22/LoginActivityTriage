using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace LoginActivityTriage.App.ViewModels;

/// <summary>Exposes shared converter instances for use via {x:Static} in XAML.</summary>
public static class VisibilityHelper
{
    public static readonly IValueConverter BoolToVisible = new BoolToVisibilityConverter();

    private sealed class BoolToVisibilityConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is true ? Visibility.Visible : Visibility.Collapsed;

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is Visibility.Visible;
    }
}
