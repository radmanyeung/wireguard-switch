using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckWorkflowTests
{
    private const string OriginalKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private static readonly string ReplacementKey = Key(32);
    private static readonly string ReplacementKey2 = Key(64);
    private static readonly string ReplacementKey3 = Key(96);

    [Fact]
    public async Task FailedOriginal_CommitsOnlyFirstVerifiedSameCountryCandidate()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(server.HostName == "uk6001.nordvpn.com", "HandshakeFailed", "GB"))
        };
        adapter.Candidates.AddRange([
            new("uk6000.nordvpn.com", config.PublicKey, "GB"),
            new("uk6001.nordvpn.com", ReplacementKey, "GB"),
            new("uk6002.nordvpn.com", ReplacementKey2, "GB")]);

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Repaired);
        result.Endpoint.Should().Be("uk6001.nordvpn.com:51820");
        result.Reason.Should().Be("ReplacementVerifiedAndSaved");
        adapter.Committed.Select(server => server.HostName).Should().Equal("uk6001.nordvpn.com");
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "test", "commit", "restore");
    }

    [Fact]
    public async Task HealthyOriginal_ReturnsHealthyAndNeverCommits()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "GB"))
        };

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Healthy);
        result.ConfigPath.Should().Be(config.Path);
        result.Endpoint.Should().Be(config.Endpoint);
        result.Reason.Should().Be("HandshakeAndHttpsVerified");
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task AllCandidatesFail_ReturnsUnrepairedAndNeverCommits()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(
                false,
                server.HostName == "uk6002.nordvpn.com" ? "SecondFailed" : "HandshakeFailed",
                "GB"))
        };
        adapter.Candidates.AddRange([
            new("uk6001.nordvpn.com", ReplacementKey, "GB"),
            new("uk6002.nordvpn.com", ReplacementKey2, "GB")]);

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        result.Endpoint.Should().Be(config.Endpoint);
        result.Reason.Should().Be("SecondFailed");
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task WrongCountryProbe_NeverCommits()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(server.HostName == config.HostName
                ? new ConfigCheckProbe(false, "HandshakeFailed", "GB")
                : new ConfigCheckProbe(true, "OK", "DE"))
        };
        adapter.Candidates.Add(new("uk6001.nordvpn.com", ReplacementKey, "GB"));

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task SuccessfulOriginalWithWrongCountry_IsNotHealthy_AndDoesNotCommitOriginal()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(server.HostName == config.HostName
                ? new ConfigCheckProbe(true, "OK", "US")
                : new ConfigCheckProbe(false, "HandshakeFailed", "GB"))
        };
        adapter.Candidates.Add(new("uk6001.nordvpn.com", ReplacementKey, "GB"));

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().NotBe(ConfigCheckStatus.Healthy);
        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        adapter.Committed.Should().BeEmpty();
        adapter.Tested.Select(server => server.HostName).Should().Equal("uk6000.nordvpn.com", "uk6001.nordvpn.com");
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task FourthValidCandidate_IsNeverTestedOrCommitted_WhenFirstThreeFail()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(server.HostName == "uk6004.nordvpn.com", "HandshakeFailed", "GB"))
        };
        adapter.Candidates.AddRange([
            new("uk6001.nordvpn.com", ReplacementKey, "GB"),
            new("uk6002.nordvpn.com", ReplacementKey2, "GB"),
            new("uk6003.nordvpn.com", ReplacementKey3, "GB"),
            new("uk6004.nordvpn.com", OriginalKey, "GB")]);

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        adapter.CandidateRequests.Should().Equal(("GB", 3));
        adapter.Tested.Select(server => server.HostName).Should().Equal(
            "uk6000.nordvpn.com",
            "uk6001.nordvpn.com",
            "uk6002.nordvpn.com",
            "uk6003.nordvpn.com");
        adapter.Tested.Should().NotContain(server => server.HostName == "uk6004.nordvpn.com");
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task IdenticalOriginal_IsNotRetried_ButSameHostWithDifferentKeyMayBeTried()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(
                server.PublicKey == ReplacementKey,
                "HandshakeFailed",
                "GB"))
        };
        adapter.Candidates.AddRange([
            new("UK6000.NORDVPN.COM", config.PublicKey, "GB"),
            new("uk6000.nordvpn.com", ReplacementKey, "GB")]);

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Repaired);
        adapter.Tested.Should().HaveCount(2);
        adapter.Tested[1].PublicKey.Should().Be(ReplacementKey);
        adapter.Committed.Select(server => server.PublicKey).Should().Equal(ReplacementKey);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "test", "commit", "restore");
    }

    [Fact]
    public async Task CandidateUse_IsBoundedToThree_AndInvalidCountryOrKeyIsSkipped()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(server.HostName == "uk6002.nordvpn.com", "HandshakeFailed", "GB"))
        };
        adapter.Candidates.AddRange([
            new("de6000.nordvpn.com", ReplacementKey, "DE"),
            new("uk6001.nordvpn.com", "invalid-key", "GB"),
            new("uk6002.nordvpn.com", ReplacementKey2, "GB"),
            new("uk6003.nordvpn.com", ReplacementKey3, "GB"),
            new("uk6004.nordvpn.com", ReplacementKey3, "GB")]);

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Repaired);
        adapter.CandidateRequests.Should().Equal(("GB", 3));
        adapter.Tested.Select(server => server.HostName).Should().Equal("uk6000.nordvpn.com", "uk6002.nordvpn.com");
        adapter.Committed.Select(server => server.HostName).Should().Equal("uk6002.nordvpn.com");
    }

    [Fact]
    public async Task CandidateDownloadFailure_HappensBeforeBeginOrMutation()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            GetCandidates = (_, _, _) => throw new IOException("synthetic metadata failure")
        };

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        adapter.Events.Should().Equal("candidates");
        adapter.Committed.Should().BeEmpty();
        adapter.RestoreTokens.Should().BeEmpty();
    }

    [Fact]
    public async Task FatalTestError_Propagates_AndRestoreStillRuns()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => throw new IOException("synthetic test failure")
        };

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        adapter.Committed.Should().BeEmpty();
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task StopOriginalError_Propagates_AndRestoreStillRunsAfterBegin()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Stop = (_, _) => throw new IOException("synthetic stop failure")
        };

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        adapter.Committed.Should().BeEmpty();
        adapter.Tested.Should().BeEmpty();
        adapter.Events.Should().Equal("candidates", "begin", "stop", "restore");
    }

    [Fact]
    public async Task RestoreException_IsPropagated_InsteadOfSuccessfulCompletion()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "GB")),
            Restore = _ => throw new IOException("synthetic restore failure")
        };

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        adapter.Committed.Should().BeEmpty();
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task CancellationDuringTesting_StillRestoresWithCancellationTokenNone()
    {
        var config = CreateConfig();
        using var cancellation = new CancellationTokenSource();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) =>
            {
                cancellation.Cancel();
                return Task.FromCanceled<ConfigCheckProbe>(cancellation.Token);
            }
        };

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, cancellation.Token))
            .Should().ThrowAsync<OperationCanceledException>();

        adapter.Committed.Should().BeEmpty();
        adapter.RestoreTokens.Should().Equal(CancellationToken.None);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task TestAndRestoreFailures_ThrowAggregateExceptionPreservingBoth()
    {
        var config = CreateConfig();
        var testFailure = new IOException("synthetic test failure");
        var restoreFailure = new InvalidOperationException("synthetic restore failure");
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => throw testFailure,
            Restore = _ => throw restoreFailure
        };

        var exception = await Record.ExceptionAsync(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None));

        var aggregate = exception.Should().BeOfType<AggregateException>().Which;
        aggregate.InnerExceptions.Should().HaveCount(2);
        aggregate.InnerExceptions[0].Should().BeSameAs(testFailure);
        aggregate.InnerExceptions[1].Should().BeSameAs(restoreFailure);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task CancellationAndRestoreFailure_ThrowAggregateExceptionPreservingBoth()
    {
        var config = CreateConfig();
        using var cancellation = new CancellationTokenSource();
        var restoreFailure = new IOException("synthetic restore failure");
        var adapter = new FakeAdapter
        {
            Probe = (_, _) =>
            {
                cancellation.Cancel();
                return Task.FromCanceled<ConfigCheckProbe>(cancellation.Token);
            },
            Restore = _ => throw restoreFailure
        };

        var exception = await Record.ExceptionAsync(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, cancellation.Token));

        var aggregate = exception.Should().BeOfType<AggregateException>().Which;
        aggregate.InnerExceptions.Should().HaveCount(2);
        aggregate.InnerExceptions[0].Should().BeAssignableTo<OperationCanceledException>();
        aggregate.InnerExceptions[1].Should().BeSameAs(restoreFailure);
        adapter.RestoreTokens.Should().Equal(CancellationToken.None);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "restore");
    }

    [Fact]
    public async Task CancellationDuringCommit_DoesNotCancelAtomicCommit_AndStillRestores()
    {
        var config = CreateConfig();
        using var cancellation = new CancellationTokenSource();
        var commitToken = CancellationToken.None;
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(server.HostName != config.HostName, "OK", "GB")),
            Commit = (_, _, _, token) =>
            {
                commitToken = token;
                cancellation.Cancel();
                return token.IsCancellationRequested ? Task.FromCanceled(token) : Task.CompletedTask;
            }
        };
        adapter.Candidates.Add(new("uk6001.nordvpn.com", ReplacementKey, "GB"));

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, cancellation.Token);

        result.Status.Should().Be(ConfigCheckStatus.Repaired);
        commitToken.Should().Be(CancellationToken.None);
        adapter.Committed.Select(server => server.HostName).Should().Equal("uk6001.nordvpn.com");
        adapter.RestoreTokens.Should().Equal(CancellationToken.None);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "test", "commit", "restore");
    }

    [Fact]
    public async Task CommitException_PropagatesUnchanged_AndRestoreRuns()
    {
        var config = CreateConfig();
        var commitFailure = new IOException("synthetic commit failure");
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(new ConfigCheckProbe(server.HostName != config.HostName, "OK", "GB")),
            Commit = (_, _, _, _) => throw commitFailure
        };
        adapter.Candidates.Add(new("uk6001.nordvpn.com", ReplacementKey, "GB"));

        var exception = await Record.ExceptionAsync(() => ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None));

        exception.Should().BeSameAs(commitFailure);
        adapter.Committed.Select(server => server.HostName).Should().Equal("uk6001.nordvpn.com");
        adapter.RestoreTokens.Should().Equal(CancellationToken.None);
        adapter.Events.Should().Equal("candidates", "begin", "stop", "test", "test", "commit", "restore");
    }

    [Fact]
    public async Task SuccessfulOriginalWithWrongCountry_ReturnsExitCountryMismatch()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "US"))
        };

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        result.Reason.Should().Be("ExitCountryMismatch");
        result.ObservedCountry.Should().Be("US");
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task SuccessfulCandidateWithWrongCountry_ReturnsExitCountryMismatch()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, server) => Task.FromResult(server.HostName == config.HostName
                ? new ConfigCheckProbe(false, "HandshakeFailed", "GB")
                : new ConfigCheckProbe(true, "OK", "US"))
        };
        adapter.Candidates.Add(new("uk6001.nordvpn.com", ReplacementKey, "GB"));

        var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);

        result.Status.Should().Be(ConfigCheckStatus.Unrepaired);
        result.Reason.Should().Be("ExitCountryMismatch");
        result.ObservedCountry.Should().Be("US");
        adapter.Committed.Should().BeEmpty();
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task RouteRestoration_RunsAfterOriginalServicesBeforeResultAndGateRelease()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var config = CreateConfig();
        var events = new List<string>();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "GB")),
            Restore = _ =>
            {
                events.Add("services-restored");
                return Task.CompletedTask;
            }
        };
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => { });

        var completed = await coordinator.RunAsync(
            _ => Task.FromResult(true),
            cancellationToken => ConfigCheckWorkflow.RunAsync(
                config,
                adapter.Object,
                cancellationToken,
                restoreRoutesAsync: async restoreToken =>
                {
                    restoreToken.Should().Be(CancellationToken.None);
                    (await gate.WaitAsync(0)).Should().BeFalse("route restoration must retain the shared gate");
                    events.Add("routes-reapplied");
                }),
            async _ =>
            {
                (await gate.WaitAsync(0)).Should().BeFalse("the result must precede gate release");
                events.Add("result-shown");
            },
            _ => { },
            CancellationToken.None);

        completed.Should().BeTrue();
        events.Should().Equal("services-restored", "routes-reapplied", "result-shown");
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task UnrepairedRouteRestorationFailure_SuppressesResultAndReleasesGate()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var gate = new SemaphoreSlim(1, 1);
        var config = CreateConfig();
        var completionCount = 0;
        var controls = new List<bool>();
        var routeFailure = new InvalidOperationException("route restoration failed");
        var adapter = new FakeAdapter();
        var coordinator = new ConfigCheckCoordinator(softwareGate, gate, () => { });

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() => coordinator.RunAsync(
            _ => Task.FromResult(true),
            cancellationToken => ConfigCheckWorkflow.RunAsync(
                config,
                adapter.Object,
                cancellationToken,
                restoreRoutesAsync: _ => throw routeFailure),
            _ =>
            {
                completionCount++;
                return Task.CompletedTask;
            },
            controls.Add,
            CancellationToken.None));

        failure.Should().BeSameAs(routeFailure);
        completionCount.Should().Be(0, "a failed route restoration must not show a result or deletion prompt");
        controls.Should().Equal(false, true);
        (await gate.WaitAsync(0)).Should().BeTrue();
        gate.Release();
    }

    [Fact]
    public async Task InactiveOriginalTunnel_RestoresServicesWithoutRouteRenewal()
    {
        var config = CreateConfig();
        var adapter = new FakeAdapter
        {
            Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "GB"))
        };
        var originalTunnelWasActive = false;
        var routeRenewalCount = 0;
        var restoreRoutes = originalTunnelWasActive
            ? (Func<CancellationToken, Task>)(_ =>
            {
                routeRenewalCount++;
                return Task.CompletedTask;
            })
            : null;

        var result = await ConfigCheckWorkflow.RunAsync(
            config,
            adapter.Object,
            CancellationToken.None,
            restoreRoutesAsync: restoreRoutes);

        result.Status.Should().Be(ConfigCheckStatus.Healthy);
        routeRenewalCount.Should().Be(0, "an inactive original tunnel must not be enabled or renewed");
        adapter.Events.Last().Should().Be("restore");
    }

    [Fact]
    public async Task CancellationDuringTesting_RestoresServicesThenRoutesWithCancellationTokenNone()
    {
        var config = CreateConfig();
        using var cancellation = new CancellationTokenSource();
        var events = new List<string>();
        var routeToken = CancellationToken.None;
        var adapter = new FakeAdapter
        {
            Probe = (_, _) =>
            {
                cancellation.Cancel();
                return Task.FromCanceled<ConfigCheckProbe>(cancellation.Token);
            },
            Restore = _ =>
            {
                events.Add("services-restored");
                return Task.CompletedTask;
            }
        };

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ConfigCheckWorkflow.RunAsync(
            config,
            adapter.Object,
            cancellation.Token,
            restoreRoutesAsync: token =>
            {
                routeToken = token;
                events.Add("routes-reapplied");
                return Task.CompletedTask;
            }));

        events.Should().Equal("services-restored", "routes-reapplied");
        routeToken.Should().Be(CancellationToken.None);
        adapter.RestoreTokens.Should().Equal(CancellationToken.None);
    }

    private static CheckedConfig CreateConfig() => new(
        @"C:\configs\GB.conf",
        "GB",
        string.Empty,
        [],
        Encoding.UTF8,
        [],
        "fingerprint",
        OriginalKey,
        OriginalKey,
        "uk6000.nordvpn.com",
        51820,
        "GB",
        "10.5.0.2",
        "uk6000.nordvpn.com:51820");

    private static string Key(int firstByte) => Convert.ToBase64String(
        Enumerable.Range(firstByte, 32).Select(value => (byte)value).ToArray());

    private sealed class FakeAdapter : IConfigCheckAdapter
    {
        private readonly IConfigCheckSession session = new FakeSession(@"C:\private-session");

        public List<ConfigCheckServer> Candidates { get; } = [];
        public List<ConfigCheckServer> Tested { get; } = [];
        public List<ConfigCheckServer> Committed { get; } = [];
        public List<string> Events { get; } = [];
        public List<(string Country, int Limit)> CandidateRequests { get; } = [];
        public List<CancellationToken> RestoreTokens { get; } = [];
        public Func<string, int, CancellationToken, Task<IReadOnlyList<ConfigCheckServer>>>? GetCandidates { get; init; }
        public Func<CheckedConfig, CancellationToken, Task<IConfigCheckSession>>? Begin { get; init; }
        public Func<IConfigCheckSession, CancellationToken, Task>? Stop { get; init; }
        public Func<CheckedConfig, ConfigCheckServer, Task<ConfigCheckProbe>>? Probe { get; init; }
        public Func<IConfigCheckSession, CheckedConfig, ConfigCheckServer, CancellationToken, Task>? Commit { get; init; }
        public Func<CancellationToken, Task>? Restore { get; init; }
        public IConfigCheckAdapter Object => this;

        public Task<IReadOnlyList<ConfigCheckServer>> GetCandidatesAsync(string country, int limit, CancellationToken token)
        {
            Events.Add("candidates");
            CandidateRequests.Add((country, limit));
            return GetCandidates?.Invoke(country, limit, token)
                ?? Task.FromResult<IReadOnlyList<ConfigCheckServer>>(Candidates);
        }

        public Task<IConfigCheckSession> BeginAsync(CheckedConfig config, CancellationToken token, string? derivedConfigPath = null)
        {
            Events.Add("begin");
            return Begin?.Invoke(config, token) ?? Task.FromResult(session);
        }

        public Task StopOriginalAsync(IConfigCheckSession session, CancellationToken token)
        {
            Events.Add("stop");
            return Stop?.Invoke(session, token) ?? Task.CompletedTask;
        }

        public Task<ConfigCheckProbe> TestAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token)
        {
            Events.Add("test");
            Tested.Add(server);
            return Probe?.Invoke(config, server)
                ?? Task.FromResult(new ConfigCheckProbe(false, "HandshakeFailed", config.Country));
        }

        public Task CommitAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token)
        {
            Events.Add("commit");
            Committed.Add(server);
            return Commit?.Invoke(session, config, server, token) ?? Task.CompletedTask;
        }

        public async Task RestoreAsync(
            IConfigCheckSession session,
            CancellationToken token,
            Func<ConfigCheckRestoreContext, CancellationToken, Task>? reconcileDerivedConfigAsync = null,
            Func<ConfigCheckRecoveredService, CancellationToken, Task>? serviceRestoredAsync = null)
        {
            Events.Add("restore");
            RestoreTokens.Add(token);
            if (Restore is not null) await Restore(token);
            if (serviceRestoredAsync is not null)
            {
                await serviceRestoredAsync(
                    new ConfigCheckRecoveredService(@"C:\configs\GB.conf", "WireGuardTunnel$GB"),
                    CancellationToken.None);
            }
        }

        public Task RecycleUnrepairedAsync(CheckedConfig config, CancellationToken token)
        {
            Events.Add("recycle");
            return Task.CompletedTask;
        }

        private sealed record FakeSession(string PrivateRoot) : IConfigCheckSession;
    }
}
