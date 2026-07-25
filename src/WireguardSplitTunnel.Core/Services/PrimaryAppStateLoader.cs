using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class PrimaryAppStateLoader
{
    public static AppState Load(StateStore store)
    {
        var state = store.Load();
        var openAiMigration = LegacyOpenAiPresetMigrationService.Migrate(state);
        var claudeMigration = LegacyClaudePresetMigrationService.Migrate(state);
        if (openAiMigration.Added > 0 || claudeMigration.Added > 0)
        {
            store.Save(state);
        }

        return state;
    }
}
