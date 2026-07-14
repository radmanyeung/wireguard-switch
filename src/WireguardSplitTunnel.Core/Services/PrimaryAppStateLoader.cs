using WireguardSplitTunnel.Core.Models;

namespace WireguardSplitTunnel.Core.Services;

public static class PrimaryAppStateLoader
{
    public static AppState Load(StateStore store)
    {
        var state = store.Load();
        var migration = LegacyOpenAiPresetMigrationService.Migrate(state);
        if (migration.Added > 0)
        {
            store.Save(state);
        }

        return state;
    }
}
