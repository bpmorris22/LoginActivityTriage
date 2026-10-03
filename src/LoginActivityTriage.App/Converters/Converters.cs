using System.Globalization;
using System.Windows.Data;

namespace LoginActivityTriage.App.Converters;

/// <summary>Renders a nullable bool ElevatedToken as Yes / No / blank.</summary>
public sealed class ElevatedToTextConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value switch
        {
            true => "Yes",
            false => "No",
            _ => string.Empty,
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Renders a bool as Yes / No.</summary>
public sealed class BoolToYesNoConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? "Yes" : "No";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Renders a DateTimeOffset as UTC "yyyy-MM-dd HH:mm:ssZ" (blank for MinValue).</summary>
public sealed class UtcTimeConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is DateTimeOffset t && t != DateTimeOffset.MinValue
            ? t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "Z"
            : string.Empty;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
