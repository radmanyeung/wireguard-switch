using FluentAssertions;
using WireguardSplitTunnel.Core.Models;
using WireguardSplitTunnel.Core.Services;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class PrimaryAppStateLoaderTests
{
    private static readonly string[] LegacyDomains =
    [
        "chatgpt.com",
        "*.chatgpt.com",
        "openai.com",
        "*.openai.com",
        "auth.openai.com",
        "api.openai.com",
        "platform.openai.com",
        "oaistatic.com",
        "*.oaistatic.com",
        "oaiusercontent.com",
        "*.oaiusercontent.com"
    ];

    private static readonly string[] HelperDomains =
    [
        "files.oaiusercontent.com",
        "challenges.cloudflare.com",
        "cdn.auth0.com"
    ];

    private static readonly string[] LegacyClaudeDomains =
    [
        "claude.ai",
        "*.claude.ai",
        "anthropic.com",
        "*.anthropic.com",
        "api.anthropic.com",
        "console.anthropic.com"
    ];

    private static readonly string[] ClaudeHelperDomains =
    [
        "claude.com",
        "*.claude.com",
        "downloads.claude.ai"
    ];

    [Fact]
    public void Load_CompleteLegacyState_MigratesAndPersistsHelpers()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyState());

            var loaded = PrimaryAppStateLoader.Load(store);
            var persisted = store.Load();

            AssertHelperRules(loaded);
            AssertHelperRules(persisted);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void StateStoreLoad_CompleteLegacyState_RemainsMigrationFree()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyState());

            var loaded = store.Load();

            GetHelperRules(loaded).Should().BeEmpty();
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void Load_CompleteLegacyClaudeState_MigratesAndPersistsHelpers()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyClaudeState());

            var loaded = PrimaryAppStateLoader.Load(store);
            var persisted = store.Load();

            AssertClaudeHelperRules(loaded);
            AssertClaudeHelperRules(persisted);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void StateStoreLoad_CompleteLegacyClaudeState_RemainsMigrationFree()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            store.Save(CreateLegacyClaudeState());

            var loaded = store.Load();

            GetClaudeHelperRules(loaded).Should().BeEmpty();
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void Load_CombinedLegacyOpenAiAndClaudeState_MigratesAndPersistsBoth()
    {
        var path = CreateTestPath();
        try
        {
            var store = new StateStore(path);
            var combinedRules = LegacyDomains
                .Concat(LegacyClaudeDomains)
                .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
                .ToList();
            store.Save(new AppState(
                combinedRules,
                new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
                []));

            var loaded = PrimaryAppStateLoader.Load(store);
            var persisted = store.Load();

            AssertHelperRules(loaded);
            AssertClaudeHelperRules(loaded);
            AssertHelperRules(persisted);
            AssertClaudeHelperRules(persisted);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void Load_NonLegacyState_DoesNotRewriteStateFile()
    {
        var path = CreateTestPath();
        const string originalJson = """{"DomainRules":[{"Domain":"chatgpt.com","Enabled":true,"Mode":1}],"LastKnownResolvedIps":{},"ManagedRouteSnapshot":[]}""";

        try
        {
            File.WriteAllText(path, originalJson);
            var store = new StateStore(path);

            var loaded = PrimaryAppStateLoader.Load(store);

            GetHelperRules(loaded).Should().BeEmpty();
            GetClaudeHelperRules(loaded).Should().BeEmpty();
            File.ReadAllText(path).Should().Be(originalJson);
        }
        finally
        {
            DeleteIfPresent(path);
        }
    }

    [Fact]
    public void ApplicationStartup_UsesPrimaryLoaderForWindowsAndMac()
    {
        var windowsSource = ReadRepositoryFile(
            "src/WireguardSplitTunnel.App/MainWindow.xaml.cs");
        var macSource = ReadRepositoryFile(
            "src/WireguardSplitTunnel.MacApp/Views/MainWindow.axaml.cs");

        windowsSource.Should().Contain("state = PrimaryAppStateLoader.Load(stateStore);");
        macSource.Should().Contain("appState = PrimaryAppStateLoader.Load(stateStore);");
    }

    private static AppState CreateLegacyState() =>
        new(
            LegacyDomains
                .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
                .ToList(),
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
            []);

    private static AppState CreateLegacyClaudeState() =>
        new(
            LegacyClaudeDomains
                .Select(domain => new DomainRule(domain, true, DomainRouteMode.UseWireGuard))
                .ToList(),
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase),
            []);

    private static void AssertHelperRules(AppState state)
    {
        var helpers = GetHelperRules(state);
        helpers.Should().HaveCount(3);
        helpers.Select(rule => rule.Domain).Should().BeEquivalentTo(HelperDomains);
        helpers.Should().OnlyContain(rule =>
            rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
    }

    private static List<DomainRule> GetHelperRules(AppState state) => state.DomainRules
        .Where(rule => HelperDomains.Contains(rule.Domain, StringComparer.OrdinalIgnoreCase))
        .ToList();

    private static void AssertClaudeHelperRules(AppState state)
    {
        var helpers = GetClaudeHelperRules(state);
        helpers.Should().HaveCount(3);
        helpers.Select(rule => rule.Domain).Should().BeEquivalentTo(ClaudeHelperDomains);
        helpers.Should().OnlyContain(rule =>
            rule.Enabled && rule.Mode == DomainRouteMode.UseWireGuard);
    }

    private static List<DomainRule> GetClaudeHelperRules(AppState state) => state.DomainRules
        .Where(rule => ClaudeHelperDomains.Contains(rule.Domain, StringComparer.OrdinalIgnoreCase))
        .ToList();

    private static string CreateTestPath()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "test-temp");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, $"{Guid.NewGuid():N}.json");
    }

    private static void DeleteIfPresent(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        var root = FindRepositoryRoot();
        return File.ReadAllText(Path.Combine(
            root,
            relativePath.Replace('/', Path.DirectorySeparatorChar)));
    }

    private static string FindRepositoryRoot()
    {
        var directory = AppContext.BaseDirectory;
        while (!string.IsNullOrWhiteSpace(directory))
        {
            if (File.Exists(Path.Combine(directory, "README.md"))
                && Directory.Exists(Path.Combine(directory, "src"))
                && Directory.Exists(Path.Combine(directory, "tests")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        throw new InvalidOperationException("Repository root was not found.");
    }
}
