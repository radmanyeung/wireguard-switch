using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class PrimaryAppStateLoader
{
    public static AppState Load(StateStore store) =>
        Load(store.LoadWithMetadata, store.Save);

    internal static AppState Load(
        Func<StateLoadResult> loadWithMetadata,
        Action<AppState> save)
    {
        var loadResult = loadWithMetadata();
        var state = loadResult.State;
        var autoUpdateMigrationRequired = !loadResult.PresentPropertyNames.Contains(nameof(AppState.AutoUpdateEnabled));
        if (autoUpdateMigrationRequired)
        {
            state = state with { AutoUpdateEnabled = true };
        }

        var openAiMigration = LegacyOpenAiPresetMigrationService.Migrate(state);
        var claudeMigration = LegacyClaudePresetMigrationService.Migrate(state);
        if (autoUpdateMigrationRequired || openAiMigration.Added > 0 || claudeMigration.Added > 0)
        {
            save(state);
        }

        return state;
    }
}
