using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.App;

public partial class RunningSoftwarePickerWindow : Window
{
    private readonly List<RunningSoftwarePickerRow> allRows;
    private readonly ObservableCollection<RunningSoftwarePickerRow> visibleRows = [];

    public IReadOnlyList<RunningSoftwareCandidate> SelectedCandidates { get; private set; } = [];

    public RunningSoftwarePickerWindow(IReadOnlyList<RunningSoftwareCandidate> candidates)
    {
        InitializeComponent();
        allRows = candidates
            .Select(candidate => new RunningSoftwarePickerRow(candidate))
            .ToList();

        CandidatesGrid.ItemsSource = visibleRows;
        ApplyFilter();
    }

    private void OnSearchTextChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        var needle = SearchBox.Text.Trim();
        visibleRows.Clear();
        foreach (var row in allRows.Where(row => row.Matches(needle)))
        {
            visibleRows.Add(row);
        }

        StatusText.Text = visibleRows.Count == 0
            ? "No running apps with readable executable paths found."
            : $"{visibleRows.Count} app{(visibleRows.Count == 1 ? string.Empty : "s")} found";
    }

    private void OnAddSelectedClicked(object sender, RoutedEventArgs e)
    {
        SelectedCandidates = allRows
            .Where(row => row.Selected)
            .Select(row => row.Candidate)
            .ToArray();

        if (SelectedCandidates.Count == 0)
        {
            MessageBox.Show(this, "Select at least one running app.", "Wireguard Split Tunnel");
            return;
        }

        DialogResult = true;
    }

    private void OnCancelClicked(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private sealed class RunningSoftwarePickerRow : INotifyPropertyChanged
    {
        private bool selected;

        public RunningSoftwarePickerRow(RunningSoftwareCandidate candidate)
        {
            Candidate = candidate;
            ShortPath = ShortenPath(candidate.ExecutablePath);
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        public RunningSoftwareCandidate Candidate { get; }

        public string ProcessName => Candidate.ProcessName;

        public string ShortPath { get; }

        public bool Selected
        {
            get => selected;
            set
            {
                if (selected == value)
                {
                    return;
                }

                selected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Selected)));
            }
        }

        public bool Matches(string needle)
        {
            if (string.IsNullOrWhiteSpace(needle))
            {
                return true;
            }

            return ProcessName.Contains(needle, StringComparison.OrdinalIgnoreCase)
                || Candidate.ExecutablePath.Contains(needle, StringComparison.OrdinalIgnoreCase);
        }

        private static string ShortenPath(string path)
        {
            var directory = Path.GetDirectoryName(path);
            var fileName = Path.GetFileName(path);
            if (string.IsNullOrWhiteSpace(directory))
            {
                return fileName;
            }

            return directory.Length <= 52
                ? path
                : $"{directory[..24]}...{directory[^24..]}\\{fileName}";
        }
    }
}
