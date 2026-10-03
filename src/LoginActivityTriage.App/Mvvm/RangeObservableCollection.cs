using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace LoginActivityTriage.App.Mvvm;

/// <summary>
/// ObservableCollection that can swap its whole content with ONE Reset notification. Re-adding
/// hundreds of thousands of rows one by one raises one CollectionChanged per row and freezes
/// the DataGrid; this keeps a filter change to a single refresh.
/// </summary>
public sealed class RangeObservableCollection<T> : ObservableCollection<T>
{
    public void ReplaceAll(IEnumerable<T> items)
    {
        Items.Clear();
        foreach (var item in items) Items.Add(item);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
