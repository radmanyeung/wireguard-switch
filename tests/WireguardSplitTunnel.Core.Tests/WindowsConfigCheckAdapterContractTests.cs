using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class WindowsConfigCheckAdapterContractTests : IDisposable
{
    private const string PrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string PublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=";
    private static readonly string CandidateKey = Key(32);
    private readonly string root = Directory.CreateTempSubdirectory("wgst-adapter-contract-").FullName;
    private readonly string appDataRoot;
    private readonly CheckedConfig config;
    private readonly ConfigCheckServer candidate;

    public WindowsConfigCheckAdapterContractTests()
    {
        appDataRoot = Path.Combine(root, "app-data");
        config = CreateConfig(Path.Combine(root, "GB.conf"));
        candidate = new ConfigCheckServer("uk6001.nordvpn.com", CandidateKey, "GB");
    }

    [Theory]
    [InlineData("wireguard.exe", true)]
    [InlineData("wg.exe", true)]
    [InlineData("sc.exe", false)]
    [InlineData("curl.exe", false)]
    public void ExecutableResolution_UsesAbsoluteValidatedTrustedPaths(string fileName, bool wireGuard)
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        var expectedDirectory = wireGuard ? Path.Combine(programFiles, "WireGuard") : system32;

        var resolved = WindowsConfigCheckNative.ResolveExecutablePath(fileName, programFiles, system32);

        resolved.Should().Be(Path.Combine(expectedDirectory, fileName));
        Path.IsPathFullyQualified(resolved).Should().BeTrue();
    }

    [Fact]
    public void ExecutableResolution_RejectsMissingUnknownAndCallerSelectedPaths()
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        File.WriteAllBytes(Path.Combine(system32, "cmd.exe"), []);

        Action missing = () => WindowsConfigCheckNative.ResolveExecutablePath("netsh.exe", programFiles, system32);
        Action unknown = () => WindowsConfigCheckNative.ResolveExecutablePath("cmd.exe", programFiles, system32);
        Action absolute = () => WindowsConfigCheckNative.ResolveExecutablePath(
            Path.Combine(system32, "sc.exe"), programFiles, system32);

        missing.Should().Throw<InvalidDataException>();
        unknown.Should().Throw<InvalidDataException>();
        absolute.Should().Throw<InvalidDataException>();
    }

    [Fact]
    public void ExecutableResolution_RejectsReparsePointInTrustedDirectory()
    {
        var programFiles = Path.Combine(root, "linked-program-files");
        var system32 = Path.Combine(root, "linked-system32");
        Directory.CreateDirectory(programFiles);
        Directory.CreateDirectory(system32);
        var outside = Directory.CreateDirectory(Path.Combine(root, "outside-wireguard")).FullName;
        File.WriteAllBytes(Path.Combine(outside, "wireguard.exe"), []);
        var link = Path.Combine(programFiles, "WireGuard");
        if (!TryCreateDirectoryLink(link, outside)) return;

        Action resolve = () => WindowsConfigCheckNative.ResolveExecutablePath("wireguard.exe", programFiles, system32);

        resolve.Should().Throw<InvalidDataException>();
    }

    private (string ProgramFiles, string System32) CreateTrustedExecutableRoots()
    {
        var programFiles = Path.Combine(root, "trusted-program-files");
        var system32 = Path.Combine(root, "trusted-system32");
        var wireGuard = Directory.CreateDirectory(Path.Combine(programFiles, "WireGuard")).FullName;
        Directory.CreateDirectory(system32);
        foreach (var name in new[] { "wireguard.exe", "wg.exe" }) File.WriteAllBytes(Path.Combine(wireGuard, name), []);
        foreach (var name in new[] { "sc.exe", "curl.exe" }) File.WriteAllBytes(Path.Combine(system32, name), []);
        return (programFiles, system32);
    }

    private WindowsConfigCheckNative CreateNativeForMutationTest(
        Action<string>? afterSourceIdentityVerification = null,
        Func<string, CancellationToken, Task>? recycleFileAsync = null,
        Action<string>? afterQuarantineIdentityVerification = null,
        Func<string, CancellationToken, Task>? protectRecycleDirectoryAsync = null,
        Action<string>? beforeRecycleRollback = null)
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        var factory = new ScriptedProcessFactory(_ =>
            throw new InvalidOperationException("No native process is expected in a file mutation test."));
        return new WindowsConfigCheckNative(
            programFiles,
            system32,
            factory,
            afterSourceIdentityVerification: afterSourceIdentityVerification,
            recycleFileAsync: recycleFileAsync,
            afterQuarantineIdentityVerification: afterQuarantineIdentityVerification,
            protectRecycleDirectoryAsync: protectRecycleDirectoryAsync ?? ((path, _) =>
            {
                Directory.Exists(path).Should().BeTrue("atomic creation must precede ACL protection");
                return Task.CompletedTask;
            }),
            beforeRecycleRollback: beforeRecycleRollback);
    }

    private static ConfigCheckFileIdentity ReadIdentity(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);
        var identity = ConfigCheckParser.GetOpenedIdentity(stream);
        return new ConfigCheckFileIdentity(identity.VolumeSerialNumber, identity.FileIndex);
    }

    private ConfigCheckRecycleTransaction CreateRecycleTransaction(string source, ConfigCheckFileIdentity identity)
    {
        var transactionId = Guid.NewGuid().ToString("N");
        var privateRoot = Directory.CreateDirectory(Path.Combine(root, "native-recycle-" + transactionId)).FullName;
        var backup = Path.Combine(privateRoot, "original.bin");
        File.WriteAllBytes(backup, File.ReadAllBytes(source));
        var quarantineDirectory = Path.Combine(
            Path.GetDirectoryName(source)!,
            "." + Path.GetFileName(source) + "." + transactionId + ".wgst-recycle");
        return new ConfigCheckRecycleTransaction(
            source, backup, quarantineDirectory, Path.Combine(quarantineDirectory, Path.GetFileName(source)),
            identity, CheckedConfig.FingerprintBytes(File.ReadAllBytes(source)));
    }

    private static bool TryCreateDirectoryLink(string path, string target)
    {
        try
        {
            Directory.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        {
            return false;
        }
    }

    [Fact]
    public async Task CraftedReplacingJournal_WithOutsidePathsIsRejectedBeforeMutation()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        var outsideSource = Path.Combine(root, "outside", "attacker.conf");
        var outsideBackup = Path.Combine(root, "outside", "attacker-backup.bin");
        Directory.CreateDirectory(Path.GetDirectoryName(outsideSource)!);
        File.WriteAllBytes(outsideBackup, config.Bytes);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["SourcePath"] = outsideSource;
        journal["DisplacedPath"] = outsideBackup;
        journal["State"] = "Replacing";
        journal["StagedPath"] = Path.Combine(
            Path.GetDirectoryName(outsideSource)!,
            ".attacker.conf." + Path.GetFileName(session.PrivateRoot) + ".wgst.tmp");
        journal["ReplacementFingerprint"] = new string('a', 64);
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());
        native.Events.Clear();

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();

        native.ReplaceCalls.Should().Be(0);
        native.Events.Should().NotContain("journal-write");
        File.Exists(outsideSource).Should().BeFalse();
        File.ReadAllBytes(outsideBackup).Should().Equal(config.Bytes);
    }

    [Fact]
    public async Task CraftedJournal_WithUndefinedStateIsRejectedBeforeMutation()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["State"] = 999;
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());
        native.Events.Clear();

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();

        native.Events.Should().NotContain("journal-write");
        native.ReplaceCalls.Should().Be(0);
    }

    [Fact]
    public async Task CraftedJournal_WithNonRunningSavedServiceIsRejectedBeforeRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["Services"]![0]!["IsRunning"] = false;
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();

        native.StartedServices.Should().BeEmpty();
    }

    [Theory]
    [InlineData("GB.conf", "WireGuardTunnel$GB")]
    [InlineData("GB.conf.conf", "WireGuardTunnel$GB.conf")]
    public async Task Restore_RealServiceNameSurvivesJournalRoundTripWithNewAdapter(
        string configFileName,
        string serviceName)
    {
        serviceName.Should().Be("WireGuardTunnel$" +
            global::WireguardSplitTunnel.Core.Services.WireguardConfigCatalog.GetTunnelName(configFileName));
        var native = new FakeConfigCheckNative();
        native.Services.Add(new ConfigCheckServiceState(serviceName, "original-identity", true));
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var persisted = await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None);
        persisted.Should().Contain("\"Name\":\"" + serviceName + "\"");
        var recoveryAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await recoveryAdapter.RestoreAsync(session, CancellationToken.None);

        native.StartedServices.Should().Equal(serviceName);
        native.Services.Single().IsRunning.Should().BeTrue();
    }

    [Theory]
    [InlineData("WireGuardTunnel$../GB")]
    [InlineData("WireGuardTunnel$GB\nInjected")]
    public async Task StopOriginal_InvalidRunningServiceNameBlocksJournalAndEveryStop(string serviceName)
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        native.Services.Add(new ConfigCheckServiceState(serviceName, "invalid-service-identity", true));
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);

        await FluentActions.Awaiting(() => adapter.StopOriginalAsync(session, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>()
            .WithMessage("The saved tunnel service journal is invalid.");

        native.StoppedServices.Should().BeEmpty();
        native.Services.Should().OnlyContain(service => service.IsRunning);
        var persisted = await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None);
        using var document = JsonDocument.Parse(persisted!);
        document.RootElement.GetProperty("State").GetString().Should().Be("Begun");
        document.RootElement.GetProperty("Services").GetArrayLength().Should().Be(0);
    }

    [Theory]
    [InlineData("WireGuardTunnel$")]
    [InlineData("WireGuardTunnel$   ")]
    [InlineData("OtherService$GB")]
    [InlineData("WireGuardTunnel$../GB")]
    [InlineData("WireGuardTunnel$..\\GB")]
    [InlineData("WireGuardTunnel$.")]
    [InlineData("WireGuardTunnel$..")]
    [InlineData("WireGuardTunnel$GB ")]
    [InlineData("WireGuardTunnel$GB\nInjected")]
    [InlineData("WireGuardTunnel$GB\0Injected")]
    public async Task CraftedJournal_InvalidSavedServiceNameIsRejectedBeforeRestart(string serviceName)
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["Services"]![0]!["Name"] = serviceName;
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>()
            .WithMessage("The saved tunnel service journal is invalid.");

        native.StartedServices.Should().BeEmpty();
    }

    [Fact]
    public async Task CraftedJournal_InvalidSavedServiceFingerprintIsRejectedBeforeRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["Services"]![0]!["Identity"] = "not-a-fingerprint";
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>()
            .WithMessage("The saved tunnel service journal is invalid.");

        native.StartedServices.Should().BeEmpty();
    }

    [Fact]
    public async Task CraftedJournal_SourcePathOnlyCannotRedirectRecoveryWithValidDisplacedBackup()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        var outsideSource = Path.Combine(root, "outside-source-only", "attacker.conf");
        Directory.CreateDirectory(Path.GetDirectoryName(outsideSource)!);
        var displacedPath = Path.Combine(session.PrivateRoot, "displaced.bin");
        await native.WritePrivateFileAsync(displacedPath, config.Bytes, CancellationToken.None);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["SourcePath"] = outsideSource;
        journal["State"] = "Replacing";
        journal["StagedPath"] = Path.Combine(
            Path.GetDirectoryName(outsideSource)!,
            ".attacker.conf." + Path.GetFileName(session.PrivateRoot) + ".wgst.tmp");
        journal["ReplacementFingerprint"] = CheckedConfig.FingerprintBytes(config.WithPeerServer(candidate));
        journal["DisplacedPath"]!.GetValue<string>().Should().Be(displacedPath);
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());
        native.Events.Clear();

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.Exists(outsideSource).Should().BeFalse();
        native.ReplaceCalls.Should().Be(0);
    }

    [Fact]
    public void PrivateDirectoryAcl_GrantsOnlySystemAndAdministrators()
    {
        var path = Path.Combine(root, "private");
        const string principal = "S-1-5-21-1-2-3-500";

        var arguments = WindowsConfigCheckNative.BuildPrivateDirectoryAclArguments(path);

        arguments.Should().NotContain("*" + principal + ":(OI)(CI)F");
        arguments.Should().Contain("*S-1-5-18:(OI)(CI)F");
        arguments.Should().Contain("*S-1-5-32-544:(OI)(CI)F");
        arguments.Skip(1).Should().NotContain(argument => argument.Contains("Everyone", StringComparison.OrdinalIgnoreCase) ||
            argument.Contains("Users", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void RecycleDirectoryAclVerification_RejectsUnprotectedDirectory()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Directory.CreateDirectory(Path.Combine(root, "unprotected-recycle-directory")).FullName;

        Action verify = () => WindowsConfigCheckNative.VerifyRecycleDirectoryAcl(path);

        verify.Should().Throw<IOException>();
    }

    [Fact]
    public async Task PrivatePayloadWrite_DoesNotOverwritePlantedLinkOrFile()
    {
        var native = new WindowsConfigCheckNative();
        var privateRoot = Directory.CreateDirectory(Path.Combine(root, "payload-link")).FullName;
        var outside = Path.Combine(root, "outside-payload-target.bin");
        var payload = Path.Combine(privateRoot, "original.bin");
        var sentinel = new byte[] { 9, 8, 7 };
        File.WriteAllBytes(outside, sentinel);
        var linkCreated = TryCreateFileLink(payload, outside);
        if (!linkCreated) File.WriteAllBytes(payload, sentinel);

        var assertion = FluentActions.Awaiting(
            () => native.WritePrivateFileAsync(payload, [1, 2, 3], CancellationToken.None)).Should();
        if (linkCreated)
        {
            await assertion.ThrowAsync<InvalidDataException>();
        }
        else
        {
            await assertion.ThrowAsync<IOException>();
        }

        File.ReadAllBytes(outside).Should().Equal(sentinel);
        File.ReadAllBytes(payload).Should().Equal(sentinel);
    }

    [Fact]
    public async Task JournalStageWrite_DoesNotOverwritePlantedLinkOrFile()
    {
        var native = new WindowsConfigCheckNative();
        var privateRoot = Directory.CreateDirectory(Path.Combine(root, "journal-link")).FullName;
        var outside = Path.Combine(root, "outside-journal-target.bin");
        var sentinel = new byte[] { 9, 8, 7 };
        File.WriteAllBytes(outside, sentinel);
        var stage = Path.Combine(privateRoot, WindowsConfigCheckAdapter.SessionJournalName + ".tmp");
        var linkCreated = TryCreateFileLink(stage, outside);
        if (!linkCreated) File.WriteAllBytes(stage, sentinel);

        var assertion = FluentActions.Awaiting(() => native.WriteJournalAsync(
                privateRoot, WindowsConfigCheckAdapter.SessionJournalName, "{}", CancellationToken.None)).Should();
        if (linkCreated)
        {
            await assertion.ThrowAsync<InvalidDataException>();
        }
        else
        {
            await assertion.ThrowAsync<IOException>();
        }

        File.ReadAllBytes(outside).Should().Equal(sentinel);
        if (!File.Exists(outside)) throw new InvalidOperationException("Synthetic sentinel was removed.");
    }

    private static bool TryCreateFileLink(string path, string target)
    {
        try
        {
            File.CreateSymbolicLink(path, target);
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or PlatformNotSupportedException or IOException)
        {
            return false;
        }
    }

    [Fact]
    public async Task NetshFailure_UsesSanitizedDiagnosticWithoutLoggingRouteArguments()
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        File.WriteAllBytes(Path.Combine(system32, "netsh.exe"), []);
        var factory = new ScriptedProcessFactory(_ => new ConfigCheckNativeResult(
            1,
            "路由新增失敗：\r\n元素找不到。\r\nPrivateKey = " + PrivateKey));
        var native = new WindowsConfigCheckNative(programFiles, system32, factory);

        var failure = await Record.ExceptionAsync(() => native.DeleteProbeRouteAsync(
            "WGSTCheck-secret",
            IPAddress.Parse("1.1.1.1"),
            CancellationToken.None));

        failure.Should().BeOfType<IOException>();
        failure.Message.Should().Contain("路由新增失敗：")
            .And.Contain("元素找不到。")
            .And.NotContain(PrivateKey)
            .And.NotContain("PrivateKey")
            .And.NotContain("WGSTCheck-secret")
            .And.NotContain("1.1.1.1");
        factory.Calls.Single().Should().Contain("interface=WGSTCheck-secret");
    }

    [Fact]
    public async Task CallerCancellation_KillsAndAwaitsChildBeforeReturning()
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        var marker = Path.Combine(root, "cancelled-child-mutated.bin");
        var process = new DelayedFakeProcess(marker);
        var factory = new FakeProcessFactory(process);
        var native = new WindowsConfigCheckNative(programFiles, system32, factory);
        using var cancellation = new CancellationTokenSource();

        var run = native.RunAsync("sc.exe", [], cancellation.Token);
        await process.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        cancellation.Cancel();
        var failure = await Record.ExceptionAsync(() => run);
        var completedAtReturn = process.Completion.Task.IsCompleted;
        await process.Completion.Task.WaitAsync(TimeSpan.FromSeconds(1));

        failure.Should().BeAssignableTo<OperationCanceledException>();
        completedAtReturn.Should().BeTrue();
        process.KillCalled.Should().BeTrue();
        process.EntireProcessTree.Should().BeTrue();
        process.Mutated.Should().BeFalse();
        File.Exists(marker).Should().BeFalse();
        factory.StartInfos.Single().FileName.Should().Be(Path.Combine(system32, "sc.exe"));
    }

    [Theory]
    [InlineData("START_PENDING", ConfigCheckServiceStatus.StartPending)]
    [InlineData("STOP_PENDING", ConfigCheckServiceStatus.StopPending)]
    public void ServiceStateParser_PreservesTransitionalStates(
        string stateText,
        ConfigCheckServiceStatus expected)
    {
        var output = "SERVICE_NAME: WireGuardTunnel$GB.conf\r\n" +
            "        STATE              : 2  " + stateText + "\r\n";

        var states = WindowsConfigCheckNative.ParseTunnelServiceStates(output);

        states.Should().ContainSingle().Which.Status.Should().Be(expected);
    }

    [Fact]
    public async Task StartService_PollsUntilRunning()
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        const string name = "WireGuardTunnel$GB.conf";
        const string binaryPath = @"C:\Program Files\WireGuard\wireguard.exe /service";
        var queryCount = 0;
        var delayCount = 0;
        var factory = new ScriptedProcessFactory(arguments =>
        {
            if (arguments.SequenceEqual(["query", "state=", "all"]))
            {
                queryCount++;
                var status = queryCount switch
                {
                    1 => "STOPPED",
                    2 => "START_PENDING",
                    _ => "RUNNING"
                };
                return new ConfigCheckNativeResult(0,
                    "SERVICE_NAME: " + name + "\r\n STATE : 0 " + status + "\r\n");
            }
            if (arguments.SequenceEqual(["qc", name]))
                return new ConfigCheckNativeResult(0, "BINARY_PATH_NAME : " + binaryPath + "\r\n");
            if (arguments.SequenceEqual(["start", name]))
                return new ConfigCheckNativeResult(0, "START_PENDING\r\n");
            throw new InvalidOperationException("Unexpected synthetic sc invocation.");
        });
        var native = new WindowsConfigCheckNative(
            programFiles,
            system32,
            factory,
            delayAsync: (_, _) =>
            {
                delayCount++;
                return Task.CompletedTask;
            });
        var identity = CheckedConfig.FingerprintBytes(Encoding.UTF8.GetBytes(name + "\0" + binaryPath));
        var service = new ConfigCheckServiceState(name, identity, false, ConfigCheckServiceStatus.Stopped);

        await native.StartServiceAsync(service, CancellationToken.None);

        queryCount.Should().Be(3);
        delayCount.Should().Be(1);
        factory.Calls.Count(call => call.SequenceEqual(["start", name])).Should().Be(1);
    }

    [Fact]
    public async Task StopService_PollsUntilStopped()
    {
        var (programFiles, system32) = CreateTrustedExecutableRoots();
        const string name = "WireGuardTunnel$GB.conf";
        const string binaryPath = @"C:\Program Files\WireGuard\wireguard.exe /service";
        var queryCount = 0;
        var delayCount = 0;
        var factory = new ScriptedProcessFactory(arguments =>
        {
            if (arguments.SequenceEqual(["query", "state=", "all"]))
            {
                queryCount++;
                var status = queryCount switch
                {
                    1 => "RUNNING",
                    2 => "STOP_PENDING",
                    _ => "STOPPED"
                };
                return new ConfigCheckNativeResult(0,
                    "SERVICE_NAME: " + name + "\r\n STATE : 0 " + status + "\r\n");
            }
            if (arguments.SequenceEqual(["qc", name]))
                return new ConfigCheckNativeResult(0, "BINARY_PATH_NAME : " + binaryPath + "\r\n");
            if (arguments.SequenceEqual(["stop", name]))
                return new ConfigCheckNativeResult(0, "STOP_PENDING\r\n");
            throw new InvalidOperationException("Unexpected synthetic sc invocation.");
        });
        var native = new WindowsConfigCheckNative(
            programFiles,
            system32,
            factory,
            delayAsync: (_, _) =>
            {
                delayCount++;
                return Task.CompletedTask;
            });
        var identity = CheckedConfig.FingerprintBytes(Encoding.UTF8.GetBytes(name + "\0" + binaryPath));
        var service = new ConfigCheckServiceState(name, identity, true, ConfigCheckServiceStatus.Running);

        await native.StopServiceAsync(service, CancellationToken.None);

        queryCount.Should().Be(3);
        delayCount.Should().Be(1);
        factory.Calls.Count(call => call.SequenceEqual(["stop", name])).Should().Be(1);
    }

    [Fact]
    public async Task NativeReplacement_UsesVerifiedIdentityWithoutBackup()
    {
        var native = new WindowsConfigCheckNative();
        var source = Path.Combine(root, "native-replace.conf");
        File.WriteAllBytes(source, config.Bytes);
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);
        var replacement = config.WithPeerServer(candidate);
        var stage = Path.Combine(root, ".native-replace.conf.test.wgst.tmp");
        var replacementIdentity = await native.StageReplacementAsync(source, stage, replacement, CancellationToken.None);
        var transaction = new ConfigCheckReplacementTransaction(
            stage, source, stage + ".replace-backup", stage + ".restore-backup",
            opened.Identity, replacementIdentity, config.Fingerprint, CheckedConfig.FingerprintBytes(replacement));

        await native.AtomicReplaceAsync(transaction, _ => Task.CompletedTask, CancellationToken.None);

        File.ReadAllBytes(source).Should().Equal(replacement);
        File.Exists(stage).Should().BeFalse();
        File.Exists(stage + ".replace-backup").Should().BeFalse();
        File.Exists(stage + ".restore-backup").Should().BeFalse();
    }

    [Fact]
    public async Task NativeReplacement_SourceSwapAfterVerificationRestoresNewerFile()
    {
        var source = Path.Combine(root, "native-after-verify-replace.conf");
        var originalSwap = source + ".original-swap";
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# after-verification replacement swap\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var callbackCalls = 0;
        var native = CreateNativeForMutationTest(path =>
        {
            callbackCalls++;
            path.Should().Be(source);
            File.Move(source, originalSwap);
            File.WriteAllBytes(source, newer);
        });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);
        var stage = Path.Combine(root, ".native-after-verify-replace.conf.test.wgst.tmp");
        var replacement = config.WithPeerServer(candidate);
        var replacementIdentity = await native.StageReplacementAsync(source, stage, replacement, CancellationToken.None);
        var transaction = new ConfigCheckReplacementTransaction(
            stage, source, stage + ".replace-backup", stage + ".restore-backup",
            opened.Identity, replacementIdentity, config.Fingerprint, CheckedConfig.FingerprintBytes(replacement));

        await FluentActions.Awaiting(() => native.AtomicReplaceAsync(
                transaction, _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        callbackCalls.Should().Be(1);
        File.ReadAllBytes(source).Should().Equal(newer);
        File.ReadAllBytes(originalSwap).Should().Equal(config.Bytes);
        File.Exists(stage + ".replace-backup").Should().BeFalse();
        File.Exists(stage + ".restore-backup").Should().BeFalse();
    }

    [Fact]
    public async Task NativeRecycle_SourceSwapAfterVerificationNeverRestoresOrRecyclesNewerFile()
    {
        var source = Path.Combine(root, "native-after-verify-recycle.conf");
        var originalSwap = source + ".original-swap";
        var recycled = Path.Combine(root, "synthetic-recycled-newer.bin");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# after-verification recycle swap\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var recycleCalls = 0;
        var native = CreateNativeForMutationTest(
            path =>
            {
                path.Should().Be(source);
                File.Move(source, originalSwap);
                File.WriteAllBytes(source, newer);
            },
            (path, _) =>
            {
                recycleCalls++;
                File.Move(path, recycled);
                return Task.CompletedTask;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);

        await FluentActions.Awaiting(() => native.RecycleFileAsync(CreateRecycleTransaction(source, opened.Identity), _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        recycleCalls.Should().Be(0);
        File.Exists(recycled).Should().BeFalse();
        File.Exists(source).Should().BeFalse("an unauthenticated source swap must not be restored");
        File.ReadAllBytes(originalSwap).Should().Equal(config.Bytes);
        File.ReadAllBytes(Path.Combine(Directory.GetDirectories(root, "*.wgst-recycle").Should().ContainSingle().Subject, Path.GetFileName(source)))
            .Should().Equal(newer);
    }

    [Fact]
    public async Task NativeRecycle_RecyclesExpectedFileFromVerifiedQuarantine()
    {
        var source = Path.Combine(root, "native-verified-quarantine.conf");
        var recycled = Path.Combine(root, "synthetic-recycled-original.bin");
        File.WriteAllBytes(source, config.Bytes);
        string? quarantine = null;
        ConfigCheckFileIdentity? recycledIdentity = null;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                quarantine = path;
                recycledIdentity = ReadIdentity(path);
                File.Move(path, recycled);
                return Task.CompletedTask;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);

        await native.RecycleFileAsync(CreateRecycleTransaction(source, opened.Identity), _ => Task.CompletedTask, CancellationToken.None);

        quarantine.Should().NotBeNull();
        quarantine.Should().NotBe(source);
        recycledIdentity.Should().Be(opened.Identity);
        File.Exists(source).Should().BeFalse();
        File.Exists(quarantine).Should().BeFalse();
        File.ReadAllBytes(recycled).Should().Equal(config.Bytes);
    }

    [Fact]
    public async Task NativeRecycle_InPlaceContentChangeAfterValidationIsNotRecycled()
    {
        var source = Path.Combine(root, "native-in-place-content-change.conf");
        var recycled = Path.Combine(root, "synthetic-recycled-in-place-change.bin");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# in-place content change\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var sourceIdentity = ReadIdentity(source);
        var transaction = CreateRecycleTransaction(source, sourceIdentity);
        var recycleCalls = 0;
        var afterValidationCalls = 0;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                recycleCalls++;
                File.Move(path, recycled);
                return Task.CompletedTask;
            },
            afterQuarantineIdentityVerification: path =>
            {
                afterValidationCalls++;
                File.WriteAllBytes(path, newer);
                ReadIdentity(path).Should().Be(sourceIdentity, "the test must mutate content without replacing the file");
            });

        await FluentActions.Awaiting(() => native.RecycleFileAsync(transaction, _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        afterValidationCalls.Should().Be(1);
        recycleCalls.Should().Be(0);
        File.Exists(recycled).Should().BeFalse();
        File.Exists(source).Should().BeFalse("the changed file must remain quarantined for recovery");
        File.ReadAllBytes(transaction.QuarantinePath).Should().Equal(newer);
        ReadIdentity(transaction.QuarantinePath).Should().Be(sourceIdentity);
    }

    [Fact]
    public async Task NativeRecycle_QuarantineSwapAfterValidationNeverRecyclesSubstitute()
    {
        var source = Path.Combine(root, "native-after-quarantine-validation.conf");
        var verifiedOriginal = Path.Combine(root, "verified-quarantined-original.bin");
        var recycled = Path.Combine(root, "synthetic-recycled-substitute.bin");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# post-validation quarantine swap\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var recycleCalls = 0;
        var afterValidationCalls = 0;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                recycleCalls++;
                File.Move(path, recycled);
                return Task.CompletedTask;
            },
            afterQuarantineIdentityVerification: path =>
            {
                afterValidationCalls++;
                File.Move(path, verifiedOriginal);
                File.WriteAllBytes(path, newer);
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);

        await FluentActions.Awaiting(() => native.RecycleFileAsync(CreateRecycleTransaction(source, opened.Identity), _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        afterValidationCalls.Should().Be(1);
        recycleCalls.Should().Be(0);
        File.Exists(recycled).Should().BeFalse();
        File.ReadAllBytes(verifiedOriginal).Should().Equal(config.Bytes);
        File.Exists(source).Should().BeFalse("an unauthenticated substitute must never be restored");
        File.ReadAllBytes(Path.Combine(Directory.GetDirectories(root, "*.wgst-recycle").Should().ContainSingle().Subject, Path.GetFileName(source)))
            .Should().Equal(newer);
    }

    [Fact]
    public async Task NativeRecycle_DirectorySubstitutionBetweenProtectionAndLockIsBlocked()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = Path.Combine(root, "native-acquisition-window.conf");
        var recycled = Path.Combine(root, "synthetic-recycled-after-acquisition-lock.bin");
        File.WriteAllBytes(source, config.Bytes);
        var renameDenied = false;
        var substituteCreated = false;
        var substituteReceivedSource = false;
        var recycleCalls = 0;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                recycleCalls++;
                substituteReceivedSource = substituteCreated;
                File.Move(path, recycled);
                return Task.CompletedTask;
            },
            protectRecycleDirectoryAsync: (path, _) =>
            {
                if (!Directory.Exists(path)) Directory.CreateDirectory(path);
                try
                {
                    Directory.Move(path, path + ".substituted");
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    renameDenied = true;
                }
                if (!renameDenied)
                {
                    Directory.CreateDirectory(path);
                    substituteCreated = true;
                }
                return Task.CompletedTask;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);

        await native.RecycleFileAsync(
            CreateRecycleTransaction(source, opened.Identity), _ => Task.CompletedTask, CancellationToken.None);

        renameDenied.Should().BeTrue("atomic creation must return an already-held non-delete-shared handle");
        substituteCreated.Should().BeFalse();
        substituteReceivedSource.Should().BeFalse();
        recycleCalls.Should().Be(1);
        File.ReadAllBytes(recycled).Should().Equal(config.Bytes);
    }

    [Fact]
    public async Task NativeRecycle_RollbackRetainsDirectoryLockAndRestoresAuthenticatedOriginal()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = Path.Combine(root, "native-authenticated-rollback.conf");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# rollback directory substitute\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var transaction = CreateRecycleTransaction(source, ReadIdentity(source));
        var substitutedDirectory = transaction.QuarantineDirectory + ".substituted";
        var renameDenied = false;
        var substituteCreated = false;
        var recycleCalls = 0;
        var beforeRollbackCalls = 0;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (_, _) =>
            {
                recycleCalls++;
                throw new IOException("Synthetic recycle sink failure.");
            },
            beforeRecycleRollback: path =>
            {
                beforeRollbackCalls++;
                path.Should().Be(transaction.QuarantineDirectory);
                try
                {
                    Directory.Move(path, substitutedDirectory);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    renameDenied = true;
                }
                if (renameDenied) return;
                Directory.CreateDirectory(path);
                File.WriteAllBytes(transaction.QuarantinePath, newer);
                substituteCreated = true;
            });

        await FluentActions.Awaiting(() => native.RecycleFileAsync(transaction, _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        beforeRollbackCalls.Should().Be(1);
        renameDenied.Should().BeTrue("rollback must retain the non-delete-shared directory handle");
        substituteCreated.Should().BeFalse();
        recycleCalls.Should().Be(1);
        File.ReadAllBytes(source).Should().Equal(config.Bytes);
        File.Exists(transaction.QuarantinePath).Should().BeFalse();
        Directory.Exists(substitutedDirectory).Should().BeFalse();
    }

    [Fact]
    public async Task NativeRecycle_DirectorySubstitutionAfterFinalValidationIsBlocked()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = Path.Combine(root, "native-directory-substitution.conf");
        var recycled = Path.Combine(root, "synthetic-recycled-after-directory-lock.bin");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# directory substitute\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var renameDenied = false;
        var substituteCreated = false;
        var recycleCalls = 0;
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                recycleCalls++;
                File.ReadAllBytes(path).Should().Equal(config.Bytes);
                File.Move(path, recycled);
                return Task.CompletedTask;
            },
            afterQuarantineIdentityVerification: path =>
            {
                var directory = Path.GetDirectoryName(path)!;
                try
                {
                    Directory.Move(directory, directory + ".substituted");
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    renameDenied = true;
                }
                if (renameDenied) return;
                Directory.CreateDirectory(directory);
                File.WriteAllBytes(path, newer);
                substituteCreated = true;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);

        await native.RecycleFileAsync(
            CreateRecycleTransaction(source, opened.Identity), _ => Task.CompletedTask, CancellationToken.None);

        renameDenied.Should().BeTrue("the quarantine directory handle must deny delete sharing");
        substituteCreated.Should().BeFalse();
        recycleCalls.Should().Be(1);
        File.ReadAllBytes(recycled).Should().Equal(config.Bytes);
        File.Exists(source).Should().BeFalse();
    }

    [Fact]
    public async Task NativeRecycle_SourceReappearingAtSinkBlocksCompletionAndIsRetained()
    {
        var source = Path.Combine(root, "native-source-reappears-at-sink.conf");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# source reappeared at recycle sink\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var native = CreateNativeForMutationTest(
            recycleFileAsync: (path, _) =>
            {
                File.WriteAllBytes(source, newer);
                File.Delete(path);
                return Task.CompletedTask;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);
        var phases = new List<ConfigCheckRecyclePhase>();

        await FluentActions.Awaiting(() => native.RecycleFileAsync(
                CreateRecycleTransaction(source, opened.Identity),
                progress =>
                {
                    phases.Add(progress.Phase);
                    return Task.CompletedTask;
                },
                CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        phases.Should().Equal(ConfigCheckRecyclePhase.Quarantined);
        File.ReadAllBytes(source).Should().Equal(newer);
    }

    [Fact]
    public async Task NativeRecycleRecovery_DirectorySubstitutionAfterValidationIsBlocked()
    {
        if (!OperatingSystem.IsWindows()) return;
        var source = Path.Combine(root, "native-recovery-directory-substitution.conf");
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# recovery directory substitute\r\n");
        File.WriteAllBytes(source, config.Bytes);
        var renameDenied = false;
        var substituteCreated = false;
        var native = CreateNativeForMutationTest(
            afterQuarantineIdentityVerification: path =>
            {
                var directory = Path.GetDirectoryName(path)!;
                try
                {
                    Directory.Move(directory, directory + ".substituted");
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    renameDenied = true;
                }
                if (renameDenied) return;
                Directory.CreateDirectory(directory);
                File.WriteAllBytes(path, newer);
                substituteCreated = true;
            });
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);
        var transaction = CreateRecycleTransaction(source, opened.Identity);
        Directory.CreateDirectory(transaction.QuarantineDirectory);
        File.Move(source, transaction.QuarantinePath);

        await native.RecoverRecycleAsync(
            transaction, ConfigCheckRecyclePhase.Quarantined, _ => Task.CompletedTask, CancellationToken.None);

        renameDenied.Should().BeTrue("recovery must hold the same non-delete-shared directory handle");
        substituteCreated.Should().BeFalse();
        File.ReadAllBytes(source).Should().Equal(config.Bytes);
        Directory.Exists(transaction.QuarantineDirectory).Should().BeFalse();
    }

    [Fact]
    public async Task NativeMutations_RejectWrongOpenedIdentityBeforeChangingSource()
    {
        var native = new WindowsConfigCheckNative();
        var source = Path.Combine(root, "native-identity.conf");
        File.WriteAllBytes(source, config.Bytes);
        var opened = await native.ReadSourceFileAsync(source, CancellationToken.None);
        var wrongIdentity = new ConfigCheckFileIdentity(
            opened.Identity.VolumeSerialNumber, opened.Identity.FileIndex ^ 1);
        var stage = Path.Combine(root, ".native-identity.conf.test.wgst.tmp");
        var replacement = config.WithPeerServer(candidate);
        var replacementIdentity = await native.StageReplacementAsync(source, stage, replacement, CancellationToken.None);
        var transaction = new ConfigCheckReplacementTransaction(
            stage, source, stage + ".replace-backup", stage + ".restore-backup",
            wrongIdentity, replacementIdentity, config.Fingerprint, CheckedConfig.FingerprintBytes(replacement));

        await FluentActions.Awaiting(() => native.AtomicReplaceAsync(
                transaction, _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        await FluentActions.Awaiting(() => native.RecycleFileAsync(CreateRecycleTransaction(source, wrongIdentity), _ => Task.CompletedTask, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(source).Should().Equal(config.Bytes);
        File.Exists(stage).Should().BeTrue();
    }

    [Fact]
    public async Task NativeRecoveryReplacement_AllowsVerifiedMissingSource()
    {
        var native = new WindowsConfigCheckNative();
        var source = Path.Combine(root, "native-missing-recovery.conf");
        var stage = Path.Combine(root, ".native-missing-recovery.conf.test.recovery.tmp");
        await native.StageReplacementAsync(source, stage, config.Bytes, CancellationToken.None);

        await native.MoveStagedFileToMissingSourceAsync(stage, source, CancellationToken.None);

        File.ReadAllBytes(source).Should().Equal(config.Bytes);
        File.Exists(stage).Should().BeFalse();
    }

    [Fact]
    public async Task ProbeFailure_RemovesOwnedTunnelBeforeReturning()
    {
        var native = new FakeConfigCheckNative { InstallExitCode = 0, HandshakeOutput = "peer\t0\n" };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        probe.Success.Should().BeFalse();
        native.Events.Should().EndWith(["verify-inactive", "delete-temp", "journal-write", "journal-clear"]);
        native.ActiveTunnelName.Should().BeNull();
        native.RouteAddress.Should().BeNull();
    }

    [Fact]
    public async Task ConcurrentSourceChange_BlocksCommitAndRecycle()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        File.WriteAllText(config.Path, config.Text + "\r\n# concurrent synthetic edit\r\n", new UTF8Encoding(false));

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.RecycleCalls.Should().Be(0);
        native.ReplaceCalls.Should().Be(0);
    }

    [Fact]
    public async Task Candidates_DownloadCountriesThenSameCountryRecommendationsOverHttps()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        var selected = await adapter.GetCandidatesAsync("GB", 2, CancellationToken.None);

        selected.Should().ContainSingle();
        selected[0].HostName.Should().Be("uk6001.nordvpn.com");
        native.HttpUris.Should().HaveCount(2);
        native.HttpUris.Should().OnlyContain(uri => uri.Scheme == Uri.UriSchemeHttps);
        native.HttpUris[0].AbsolutePath.Should().Contain("countries");
        native.HttpUris[1].AbsolutePath.Should().Contain("recommendations");
        native.HttpUris[1].Query.Should().Contain("country_id").And.Contain("42");
        native.Events.Should().NotContain("create-private");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    public async Task Candidates_RejectUnboundedLimitsBeforeHttp(int limit)
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.GetCandidatesAsync("GB", limit, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();

        native.HttpUris.Should().BeEmpty();
    }

    [Fact]
    public async Task MetadataFailure_HappensBeforeBeginOrMutation()
    {
        var native = new FakeConfigCheckNative { CountriesJson = "[]" };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.GetCandidatesAsync("GB", 3, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();
        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, adapter, CancellationToken.None))
            .Should().ThrowAsync<InvalidDataException>();

        native.Events.Should().NotContain("create-private");
        native.Events.Should().NotContain("service-stop");
        native.ReplaceCalls.Should().Be(0);
    }

    [Fact]
    public async Task Begin_BackupAndJournalPrecedeOriginalStop()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        var session = await adapter.BeginAsync(config, CancellationToken.None);
        await adapter.StopOriginalAsync(session, CancellationToken.None);

        native.Events.Should().ContainInOrder("create-private", "backup", "journal-write", "service-snapshot", "journal-write", "service-stop");
        var backup = await native.ReadPrivateFileAsync(Path.Combine(session.PrivateRoot, "original.bin"), CancellationToken.None);
        backup.Should().Equal(config.Bytes);
        native.Services.Single().IsRunning.Should().BeFalse();
    }

    [Fact]
    public async Task StopOriginal_RecordsOnlyOriginallyRunningTunnelServices()
    {
        var native = new FakeConfigCheckNative();
        var running = OriginalService();
        var stopped = new ConfigCheckServiceState("WireGuardTunnel$stopped.conf", "identity-stopped", false);
        var unrelated = new ConfigCheckServiceState("OtherService", "identity-other", true);
        native.Services.AddRange([running, stopped, unrelated]);
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);

        await adapter.StopOriginalAsync(session, CancellationToken.None);

        native.StoppedServices.Should().Equal(running.Name);
        native.JournalTexts(session.PrivateRoot).Should().Contain(running.Name).And.NotContain(stopped.Name).And.NotContain(unrelated.Name);
    }

    [Theory]
    [InlineData(ConfigCheckServiceStatus.StartPending)]
    [InlineData(ConfigCheckServiceStatus.StopPending)]
    public async Task StopOriginal_TransitionalServiceBlocksStopStateAndMutation(ConfigCheckServiceStatus status)
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService() with { IsRunning = false, Status = status });
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);

        await FluentActions.Awaiting(() => adapter.StopOriginalAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StoppedServices.Should().BeEmpty();
        native.JournalTexts(session.PrivateRoot).Should().NotContain("StopRequested");
    }

    [Theory]
    [InlineData(ConfigCheckServiceStatus.StartPending)]
    [InlineData(ConfigCheckServiceStatus.StopPending)]
    public async Task Restore_TransitionalServiceBlocksEveryRestart(ConfigCheckServiceStatus status)
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.Services[0] = native.Services[0] with { IsRunning = false, Status = status };

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StartedServices.Should().BeEmpty();
    }

    [Fact]
    public async Task HealthyProbe_UsesFreshPeerExactRouteAndBoundCurlArguments()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = CandidateKey + "\t" + (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 10) + "\n",
            TraceOutput = "ip=203.0.113.8\nloc=GB\n"
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        native.ObservedCurlOutput.Should().Be("ip=203.0.113.8\nloc=GB\n");
        probe.Should().Be(new ConfigCheckProbe(true, "OK", "GB"));
        native.RouteHistory.Should().ContainSingle().Which.Should().Be("1.1.1.1/32");
        var install = native.ProcessCalls.Single(call => call.FileName == "wireguard.exe");
        install.Arguments.Should().HaveCount(2);
        install.Arguments[0].Should().Be("/installtunnelservice");
        install.Arguments[1].Should().StartWith(session.PrivateRoot).And.EndWith(".conf");
        native.ProcessCalls.Should().Contain(call => call.FileName == "wg.exe" &&
            call.Arguments.SequenceEqual(new[] { "show", native.LastOwnedTunnelName!, "latest-handshakes" }));
        var curl = native.ProcessCalls.Single(call => call.FileName == "curl.exe");
        curl.Arguments.Should().Equal(WindowsConfigCheckPrimitives.BuildCurlArguments("1.1.1.1", config.SourceAddress));
        native.DnsNames.Should().Equal(candidate.HostName, "www.cloudflare.com");
    }

    [Fact]
    public async Task StaleHandshake_DoesNotAddRouteOrRunHttps()
    {
        var native = new FakeConfigCheckNative { HandshakeOutput = CandidateKey + "\t0\n" };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        probe.Success.Should().BeFalse();
        probe.Reason.Should().Be("HandshakeFailed");
        native.RouteHistory.Should().BeEmpty();
        native.ProcessCalls.Should().NotContain(call => call.FileName == "curl.exe");
    }

    [Fact]
    public async Task InstallFailure_IsProbeFailureAndNeverAddsRoute()
    {
        var native = new FakeConfigCheckNative { InstallExitCode = 5 };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        probe.Success.Should().BeFalse();
        probe.Reason.Should().Be("TunnelInstallFailed");
        native.RouteHistory.Should().BeEmpty();
        native.Events.Should().EndWith(["verify-inactive", "delete-temp", "journal-write", "journal-clear"]);
    }

    [Fact]
    public async Task HttpsFailure_IsNotSuccessAndCleansOwnedArtifacts()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            CurlExitCode = 28,
            NativeErrorOutput = "raw output " + PrivateKey
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        probe.Success.Should().BeFalse();
        probe.Reason.Should().Be("HttpsFailed");
        probe.Reason.Should().NotContain(PrivateKey).And.NotContain("raw output");
        native.ActiveTunnelName.Should().BeNull();
        native.RouteAddress.Should().BeNull();
    }

    [Fact]
    public async Task WrongCountry_IsNotSuccessAndReportsExitCountryMismatch()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            TraceOutput = "loc=US\n"
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);

        probe.Success.Should().BeFalse();
        probe.Reason.Should().Be("ExitCountryMismatch");
        probe.ObservedCountry.Should().Be("US");
    }

    [Fact]
    public async Task DnsFailure_OccursBeforeOwnedTunnelInstall()
    {
        var native = new FakeConfigCheckNative { DnsFailure = true };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.ProcessCalls.Should().NotContain(call => call.FileName == "wireguard.exe");
        native.ReplaceCalls.Should().Be(0);
    }

    [Fact]
    public async Task Commit_ReplacesOnlyVerifiedPeerBytesAndRetainsDisplacedSource()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);

        await adapter.CommitAsync(session, config, candidate, new CancellationToken(canceled: true));

        var expected = config.WithPeerServer(candidate);
        var current = await native.ReadSourceFileAsync(config.Path, CancellationToken.None);
        current.Bytes.Should().Equal(expected);
        var displaced = await native.ReadPrivateFileAsync(Path.Combine(session.PrivateRoot, "displaced.bin"), CancellationToken.None);
        displaced.Should().Equal(config.Bytes);
        native.Events.Should().ContainInOrder("read-source", "write-displaced", "journal-write", "stage", "replace", "read-source", "journal-write");
        native.LastStagedPath.Should().StartWith(Path.GetDirectoryName(config.Path));
    }

    [Fact]
    public async Task SourceSwapImmediatelyBeforeReplace_PreservesNewerFile()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# renamed newer source\r\n");
        native.BeforeReplace = (_, source, _) =>
        {
            File.Move(source, source + ".pre-replace-swap");
            File.WriteAllBytes(source, newer);
        };

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(newer);
    }

    [Fact]
    public async Task SourceSwapImmediatelyBeforeRecycle_PreservesNewerFile()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# renamed newer recycle source\r\n");
        native.BeforeRecycle = source =>
        {
            File.Move(source, source + ".pre-recycle-swap");
            File.WriteAllBytes(source, newer);
        };

        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(newer);
    }

    [Fact]
    public async Task Commit_JournalsSameDirectoryReplacementBackupBeforeMutation()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);

        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);

        native.ReplaceBackupPaths.Should().ContainSingle().Which.Should().Be(native.LastStagedPath + ".replace-backup");
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"ReplacementBackupPath\":\"" + (native.LastStagedPath + ".replace-backup").Replace("\\", "\\\\") + "\"");
        var displaced = await native.ReadPrivateFileAsync(
            Path.Combine(session.PrivateRoot, "displaced.bin"), CancellationToken.None);
        displaced.Should().Equal(config.Bytes);
    }

    [Fact]
    public async Task InterruptedReplacement_PublicRecoveryRestoresDisplacedSourceBeforeRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.BeforeReplace = (_, source, _) => File.Delete(source);
        native.ReplaceFailure = new IOException("synthetic interrupted replacement");

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var recoveredAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        await recoveredAdapter.RecoverAsync(config, CancellationToken.None);

        native.Events.Last().Should().Be("journal-write");
        (await native.ReadSourceFileAsync(config.Path, CancellationToken.None)).Bytes.Should().Equal(config.Bytes);
        native.Services.Single().IsRunning.Should().BeTrue();
        native.StartedServices.Should().Equal(native.Services[0].Name);
        Directory.GetFiles(root, "*.wgst.tmp", SearchOption.AllDirectories).Should().BeEmpty();
        Directory.GetFiles(root, "*.recovery.tmp", SearchOption.AllDirectories).Should().BeEmpty();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task InterruptedReplacement_AfterFirstReplace_RecoversAppliedContentAndRecordedArtifacts()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        string? backup = null;
        native.BeforeReplace = (stage, source, _) =>
        {
            backup = stage + ".replace-backup";
            File.Replace(stage, source, backup, ignoreMetadataErrors: true);
        };
        native.ReplaceFailure = new IOException("synthetic crash after first replacement");

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        native.RecoveryNative = CreateNativeForMutationTest();

        await adapter.RecoverAsync(config, CancellationToken.None);

        File.ReadAllBytes(config.Path).Should().Equal(config.WithPeerServer(candidate));
        File.Exists(backup).Should().BeFalse();
        File.Exists(native.LastStagedPath + ".restore-backup").Should().BeFalse();
        File.Exists(native.LastStagedPath).Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task InterruptedReplacement_AfterSwapDetection_RestoresNewerSourceWithoutFalseCompletion()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var originalSwap = config.Path + ".interrupted-original";
        var newer = Encoding.UTF8.GetBytes(config.Text + "\r\n# interrupted replacement rollback\r\n");
        string? backup = null;
        native.BeforeReplace = (stage, source, _) =>
        {
            File.Move(source, originalSwap);
            File.WriteAllBytes(source, newer);
            backup = stage + ".replace-backup";
            File.Replace(stage, source, backup, ignoreMetadataErrors: true);
        };
        native.ReplaceFailure = new IOException("synthetic crash after replacement swap detection");

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"ReplacementPhase\":\"Replaced\"")
            .And.Contain("\"DisplacedSourceIdentity\":{\"VolumeSerialNumber\":");
        native.RecoveryNative = CreateNativeForMutationTest();

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(newer);
        File.ReadAllBytes(originalSwap).Should().Equal(config.Bytes);
        File.Exists(backup).Should().BeFalse();
        File.Exists(native.LastStagedPath + ".restore-backup").Should().BeFalse();
        File.Exists(native.LastStagedPath).Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task CompletedReplacement_ReadbackStaysAppliedDuringRestore()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);
        var expected = config.WithPeerServer(candidate);

        await adapter.RestoreAsync(session, CancellationToken.None);

        (await native.ReadSourceFileAsync(config.Path, CancellationToken.None)).Bytes.Should().Equal(expected);
        native.Services.Single().IsRunning.Should().BeTrue();
    }

    [Fact]
    public async Task RepairedKillSwitchConfig_ReconcilesEnabledDerivedCopyBeforeServiceRestart()
    {
        var derivedPath = global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            config.Path,
            Path.Combine(appDataRoot, "derived-confs"));
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey)
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        ConfigCheckRestoreContext? observedContext = null;
        var reconcileCount = 0;

        var result = await ConfigCheckWorkflow.RunAsync(
            config,
            adapter,
            CancellationToken.None,
            derivedConfigPath: derivedPath,
            reconcileDerivedConfigAsync: (context, token) =>
            {
                native.StartedServices.Should().BeEmpty("the derived config must be current before the original service starts");
                token.Should().Be(CancellationToken.None);
                observedContext = context;
                reconcileCount++;
                global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.ReconcileRepairedConfigFile(
                    context.SourcePath,
                    context.DerivedConfigPath,
                    context.SourceFingerprint);
                return Task.CompletedTask;
            });

        result.Status.Should().Be(ConfigCheckStatus.Repaired);
        result.Endpoint.Should().Be(candidate.HostName + ":51820");
        reconcileCount.Should().Be(1);
        observedContext.Should().NotBeNull();
        observedContext!.SourcePath.Should().Be(config.Path);
        observedContext.DerivedConfigPath.Should().Be(derivedPath);
        native.StartedServices.Should().Equal("WireGuardTunnel$GB");
        File.ReadAllBytes(config.Path).Should().Equal(config.WithPeerServer(candidate));
        var restoredDerived = CheckedConfig.Parse(derivedPath);
        restoredDerived.Endpoint.Should().Be(candidate.HostName + ":51820");
        restoredDerived.PublicKey.Should().Be(CandidateKey);
        restoredDerived.Text.Should().Contain("AllowedIPs = 0.0.0.0/1, 128.0.0.0/1");
        restoredDerived.Text.Should().NotContain("0.0.0.0/0");
        restoredDerived.Text.Should().NotContain("::/0");
        global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.SanitizeText(restoredDerived.Text)
            .Changed.Should().BeFalse();
        File.ReadAllText(derivedPath).Should().Be(
            global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.SanitizeText(
                CheckedConfig.Parse(config.Path).Text).Text);
    }

    [Fact]
    public async Task DerivedReconciliationFailure_SuppressesResultAndBlocksRestartUntilRecoveryReconciles()
    {
        var derivedPath = global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            config.Path,
            Path.Combine(appDataRoot, "derived-confs"));
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey)
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var failure = new InvalidOperationException("synthetic derived reconciliation failure");

        await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(
            config,
            adapter,
            CancellationToken.None,
            derivedConfigPath: derivedPath,
            reconcileDerivedConfigAsync: (_, _) => throw failure))
            .Should().ThrowAsync<InvalidOperationException>();

        native.StartedServices.Should().BeEmpty();
        native.RecycleCalls.Should().Be(0);
        var journal = await native.ReadJournalAsync(
            (await native.FindJournalRootsAsync(appDataRoot, CancellationToken.None)).Single(),
            WindowsConfigCheckAdapter.SessionJournalName,
            CancellationToken.None);
        journal.Should().Contain("\"State\":\"Repaired\"");
        journal.Should().NotContain("\"State\":\"Completed\"");
        var staleDerived = File.ReadAllBytes(derivedPath);

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config.Path, CancellationToken.None))
            .Should().ThrowAsync<IOException>()
            .WithMessage("*derived config reconciliation*");

        native.StartedServices.Should().BeEmpty();
        File.ReadAllBytes(derivedPath).Should().Equal(staleDerived);

        await adapter.RecoverAsync(
            config.Path,
            CancellationToken.None,
            (context, _) =>
            {
                native.StartedServices.Should().BeEmpty();
                global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.ReconcileRepairedConfigFile(
                    context.SourcePath,
                    context.DerivedConfigPath,
                    context.SourceFingerprint);
                return Task.CompletedTask;
            });

        native.StartedServices.Should().Equal("WireGuardTunnel$GB");
        CheckedConfig.Parse(derivedPath).PublicKey.Should().Be(CandidateKey);
    }

    [Fact]
    public void DerivedReconciliation_ArbitrarySameNameFileIsNotModified()
    {
        var derivedPath = global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            config.Path,
            Path.Combine(appDataRoot, "derived-confs"));
        var repairedBytes = config.WithPeerServer(candidate);
        File.WriteAllBytes(config.Path, repairedBytes);
        var arbitraryText = File.ReadAllText(derivedPath).Replace(
            "Address = 10.5.0.2/32",
            "Address = 10.5.0.3/32",
            StringComparison.Ordinal);
        File.WriteAllText(derivedPath, arbitraryText);
        var arbitraryBytes = File.ReadAllBytes(derivedPath);

        Action reconcile = () => global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer
            .ReconcileRepairedConfigFile(
                config.Path,
                derivedPath,
                CheckedConfig.FingerprintBytes(repairedBytes));

        reconcile.Should().Throw<IOException>();
        File.ReadAllBytes(derivedPath).Should().Equal(arbitraryBytes);
        File.ReadAllBytes(config.Path).Should().Equal(repairedBytes);
    }

    [Fact]
    public async Task UnknownNewerSource_IsRetainedForManualReviewAndBlocksRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);
        var changed = Encoding.UTF8.GetBytes(config.Text + "\r\n# unknown newer content\r\n");
        File.WriteAllBytes(config.Path, changed);

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(changed);
        native.StartedServices.Should().BeEmpty();
        native.Services.Single().IsRunning.Should().BeFalse();
    }

    [Fact]
    public async Task ChangedServiceIdentity_RefusesAutomaticRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.Services[0] = native.Services[0] with { Identity = "changed-identity" };

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StartedServices.Should().BeEmpty();
    }

    [Fact]
    public async Task DifferentRunningTunnel_RefusesAutomaticRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.Services.Add(new ConfigCheckServiceState("WireGuardTunnel$other.conf", "other-identity", true));

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StartedServices.Should().BeEmpty();
    }

    [Fact]
    public async Task FailedOwnedTunnelCleanup_BlocksOriginalRestart()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = CandidateKey + "\t0\n",
            UninstallFailure = new IOException("synthetic uninstall failure")
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StartedServices.Should().BeEmpty();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.AttemptJournalName, CancellationToken.None))
            .Should().NotBeNull();
    }

    [Fact]
    public async Task CompletedJournal_PreventsDuplicateCleanupAndRestart()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await adapter.RestoreAsync(session, CancellationToken.None);
        var eventCount = native.Events.Count;
        var startCount = native.StartedServices.Count;

        await adapter.RestoreAsync(session, CancellationToken.None);

        native.Events.Should().HaveCount(eventCount);
        native.StartedServices.Should().HaveCount(startCount);
    }

    [Fact]
    public async Task FreshProcessRecovery_UsesProtectedJournalWhenFreshInputContainsReplacement()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);
        var replacement = config.WithPeerServer(candidate);
        var freshInput = CheckedConfig.Parse(config.Path);
        freshInput.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(replacement));
        freshInput.Fingerprint.Should().NotBe(config.Fingerprint);
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await freshAdapter.RecoverAsync(freshInput, CancellationToken.None);

        File.ReadAllBytes(config.Path).Should().Equal(replacement);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        (await native.ReadJournalAsync(
                session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task UnpreparedRecovery_SourceExistenceUsesNativeBoundary()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None);
        await native.WritePrivateFileAsync(
            Path.Combine(session.PrivateRoot, "displaced.bin"), config.Bytes, CancellationToken.None);
        var journal = JsonNode.Parse((await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        journal["State"] = "Replacing";
        journal["StagedPath"] = Path.Combine(
            Path.GetDirectoryName(config.Path)!,
            "." + Path.GetFileName(config.Path) + "." + Path.GetFileName(session.PrivateRoot) + ".wgst.tmp");
        journal["ReplacementFingerprint"] = CheckedConfig.FingerprintBytes(config.WithPeerServer(candidate));
        native.SetJournal(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, journal.ToJsonString());
        File.Delete(config.Path);
        native.SourceFileExistsOverride = _ => true;

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.SourceFileExistsCalls.Should().Be(1);
        native.LastStagedPath.Should().BeNull("an ambiguous source reported by native must not be overwritten");
        File.Exists(config.Path).Should().BeFalse();
    }

    [Fact]
    public async Task FreshProcessRecovery_ByPathRestoresMissingSourceAndRecordedServices()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.BeforeReplace = (_, source, _) => File.Delete(source);
        native.ReplaceFailure = new IOException("synthetic interruption with missing source");
        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        File.Exists(config.Path).Should().BeFalse();
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await freshAdapter.RecoverAsync(config.Path, CancellationToken.None);

        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        (await native.ReadJournalAsync(
                session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task FreshProcessRecovery_RejectsUnrelatedSamePathContentWithoutRestartingServices()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var unrelated = config.WithPeerServer(new ConfigCheckServer("uk6002.nordvpn.com", Key(64), "GB"));
        native.BeforeReplace = (_, source, _) => File.WriteAllBytes(source, unrelated);
        native.ReplaceFailure = new IOException("synthetic interruption after unrelated source appeared");
        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var freshInput = CheckedConfig.Parse(config.Path);
        freshInput.Fingerprint.Should().Be(CheckedConfig.FingerprintBytes(unrelated));
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => freshAdapter.RecoverAsync(freshInput, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(unrelated);
        native.StartedServices.Should().BeEmpty();
        native.Services.Single().IsRunning.Should().BeFalse();
        (await native.ReadJournalAsync(
                session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task RecoverAsync_CompletedJournalsForMultipleConfigsDoNotBlockCurrentRecovery()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        foreach (var name in new[] { "US", "DE" })
        {
            var historicalConfig = CreateConfig(Path.Combine(root, name + ".conf"));
            var historicalSession = await adapter.BeginAsync(historicalConfig, CancellationToken.None);
            await adapter.RestoreAsync(historicalSession, CancellationToken.None);
        }
        var currentSession = await adapter.BeginAsync(config, CancellationToken.None);

        await adapter.RecoverAsync(config, CancellationToken.None);

        (await native.ReadJournalAsync(
                currentSession.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task IncompleteJournal_BlocksNextBeginUntilRecoveryCompletes()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        await adapter.BeginAsync(config, CancellationToken.None);

        await FluentActions.Awaiting(() => adapter.BeginAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        await adapter.RecoverAsync(config, CancellationToken.None);
        var next = await adapter.BeginAsync(config, CancellationToken.None);
        next.PrivateRoot.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task RecycleUnrepaired_CallsInjectedRecycleExactlyOnceForSameSource()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await adapter.RecycleUnrepairedAsync(config, CancellationToken.None);

        native.RecycleCalls.Should().Be(1);
        native.RecycledPath.Should().Be(config.Path);
        File.Exists(config.Path).Should().BeFalse();
    }

    [Fact]
    public async Task RecycleFailure_LeavesSourceInPlace()
    {
        var native = new FakeConfigCheckNative { RecycleFailure = new IOException("synthetic recycle failure") };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.RecycleCalls.Should().Be(1);
        File.Exists(config.Path).Should().BeTrue();
        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
    }

    [Fact]
    public async Task RecycleInterruption_AfterMoveBeforeRecycle_RestoresVerifiedQuarantineBeforeCompletion()
    {
        var native = new FakeConfigCheckNative
        {
            CrashBeforeRecycle = new IOException("synthetic crash before recycle")
        };
        string? preparedJson = null;
        native.BeforeRecycleMove = async transaction =>
        {
            var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
            preparedJson = await native.ReadJournalAsync(
                privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None);
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        var transaction = native.LastRecycleTransaction!;
        var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
        using var prepared = JsonDocument.Parse(preparedJson!);
        prepared.RootElement.GetProperty("Phase").GetString().Should().Be("Prepared");
        prepared.RootElement.GetProperty("QuarantineDirectory").GetString().Should().Be(transaction.QuarantineDirectory);
        prepared.RootElement.GetProperty("QuarantinePath").GetString().Should().Be(transaction.QuarantinePath);
        prepared.RootElement.GetProperty("SourceFingerprint").GetString().Should().Be(transaction.SourceFingerprint);
        File.Exists(transaction.SourcePath).Should().BeFalse();
        File.ReadAllBytes(transaction.QuarantinePath).Should().Equal(config.Bytes);
        await FluentActions.Awaiting(() => adapter.BeginAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        native.RecoveryNative = CreateNativeForMutationTest();

        await new WindowsConfigCheckAdapter(native, appDataRoot).RecoverAsync(config.Path, CancellationToken.None);

        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
        File.Exists(transaction.QuarantinePath).Should().BeFalse();
        Directory.Exists(transaction.QuarantineDirectory).Should().BeFalse();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Completed\"");
    }

    [Fact]
    public async Task RecycleInterruption_AfterSinkBeforePhaseJournal_ConservativelyRestoresProtectedOriginal()
    {
        var native = new FakeConfigCheckNative
        {
            CrashAfterSinkBeforePhaseJournal = new IOException("synthetic crash before recycled phase was durable")
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        var transaction = native.LastRecycleTransaction!;
        var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
        File.Exists(transaction.SourcePath).Should().BeFalse();
        File.Exists(transaction.QuarantinePath).Should().BeFalse();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Quarantined\"");
        native.RecoveryNative = CreateNativeForMutationTest();

        await new WindowsConfigCheckAdapter(native, appDataRoot).RecoverAsync(config.Path, CancellationToken.None);

        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
        Directory.Exists(transaction.QuarantineDirectory).Should().BeFalse();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Completed\"");
    }

    [Fact]
    public async Task RecycleInterruption_AfterRecycledPhase_ReconcilesAbsentArtifactsBeforeCompletion()
    {
        var native = new FakeConfigCheckNative
        {
            CrashAfterRecycledPhase = new IOException("synthetic crash after recycled phase")
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        var transaction = native.LastRecycleTransaction!;
        var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
        File.Exists(transaction.SourcePath).Should().BeFalse();
        File.Exists(transaction.QuarantinePath).Should().BeFalse();
        Directory.Exists(transaction.QuarantineDirectory).Should().BeTrue();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Recycled\"");
        native.RecoveryNative = CreateNativeForMutationTest();

        await new WindowsConfigCheckAdapter(native, appDataRoot).RecoverAsync(config.Path, CancellationToken.None);

        File.Exists(config.Path).Should().BeFalse();
        Directory.Exists(transaction.QuarantineDirectory).Should().BeFalse();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Completed\"");
    }

    [Fact]
    public async Task RecycleRecovery_NewerSourceAndQuarantineAreRetainedWithoutCompletion()
    {
        var native = new FakeConfigCheckNative
        {
            CrashBeforeRecycle = new IOException("synthetic crash before recycle")
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var transaction = native.LastRecycleTransaction!;
        var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
        var newer = config.WithPeerServer(candidate);
        File.WriteAllBytes(config.Path, newer);
        native.RecoveryNative = CreateNativeForMutationTest();

        await FluentActions.Awaiting(() =>
                new WindowsConfigCheckAdapter(native, appDataRoot).RecoverAsync(config.Path, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(newer);
        File.ReadAllBytes(transaction.QuarantinePath).Should().Equal(config.Bytes);
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().NotContain("\"Phase\":\"Completed\"");
    }

    [Fact]
    public async Task Restore_UsesNoneTokenAndRestartsOnlyRecordedStoppedServices()
    {
        var native = new FakeConfigCheckNative();
        var running = OriginalService();
        native.Services.AddRange([
            running,
            new ConfigCheckServiceState("WireGuardTunnel$already-stopped.conf", "other", false),
            new ConfigCheckServiceState("Unrelated", "unrelated", false)]);
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter, new CancellationToken(canceled: true));

        await adapter.RestoreAsync(session, new CancellationToken(canceled: true));

        native.StartedServices.Should().Equal(running.Name);
        native.ObservedStartTokens.Should().OnlyContain(token => token == CancellationToken.None);
    }

    [Fact]
    public async Task PrivateRootAndRecyclePathAttributes_UseInjectedNativeBoundary()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await adapter.RecycleUnrepairedAsync(config, CancellationToken.None);

        native.PathAttributeChecks.Should().Contain(session.PrivateRoot);
        native.PathAttributeChecks.Should().Contain(config.Path);
    }

    [Fact]
    public async Task PartialTempConfigWrite_IsCleanedAndRecoverableWithoutAttemptJournal()
    {
        var native = new FakeConfigCheckNative { PartialTempWriteFailure = true };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        Directory.GetFiles(root, "WGSTCheck-*.conf", SearchOption.AllDirectories).Should().BeEmpty();
        await adapter.RestoreAsync(session, CancellationToken.None);
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task AttemptJournalWriteFailure_CleansKnownTempConfigAndRecoverSession()
    {
        var native = new FakeConfigCheckNative { AttemptJournalWriteFailure = true };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.AttemptJournalName, CancellationToken.None))
            .Should().BeNull();
        Directory.GetFiles(root, "WGSTCheck-*.conf", SearchOption.AllDirectories).Should().BeEmpty();
        await adapter.RestoreAsync(session, CancellationToken.None);
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task StagingDeleteFailure_PreventsCompletedJournal()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);
        File.WriteAllBytes(native.LastStagedPath!, [1, 2, 3]);
        native.StagingDeleteFailure = new IOException("synthetic staging cleanup failure");

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
        File.Exists(native.LastStagedPath).Should().BeTrue();
    }

    [Fact]
    public async Task ChangedSecondServiceIdentity_PreventsEveryOriginalRestart()
    {
        var native = new FakeConfigCheckNative();
        var first = OriginalService();
        var second = new ConfigCheckServiceState("WireGuardTunnel$second", "second-identity", true);
        native.Services.AddRange([first, second]);
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.Services[1] = native.Services[1] with { Identity = "changed-second-identity" };

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.StartedServices.Should().BeEmpty();
        native.Services.Should().OnlyContain(service => !service.IsRunning);
    }

    [Fact]
    public async Task SuccessfulProbeCleanup_ClearsOwnedStateAndRestoreIsIdempotent()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            TraceOutput = "loc=GB\n"
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        (await adapter.TestAsync(session, config, candidate, CancellationToken.None)).Success.Should().BeTrue();

        await adapter.RestoreAsync(session, CancellationToken.None);
        await adapter.RestoreAsync(session, CancellationToken.None);

        native.RouteDeleteCalls.Should().Be(1);
        var json = await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None);
        using var document = JsonDocument.Parse(json!);
        document.RootElement.GetProperty("OwnedTunnelName").ValueKind.Should().Be(JsonValueKind.Null);
        document.RootElement.GetProperty("OwnedTempConfigPath").ValueKind.Should().Be(JsonValueKind.Null);
        document.RootElement.GetProperty("OwnedRouteAddress").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task CleanupCompletionJournalFailure_RetryVerifiesAbsentRouteAndCompletesRestore()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            TraceOutput = "loc=GB\n",
            CleanupCompletionJournalWriteFailure = new IOException("synthetic cleanup completion journal failure")
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        native.RouteAddress.Should().BeNull();
        native.RouteDeleteCalls.Should().Be(1);
        native.CleanupCompletionJournalWriteFailure = null;

        await adapter.RestoreAsync(session, CancellationToken.None);
        await adapter.RestoreAsync(session, CancellationToken.None);

        native.RouteDeleteCalls.Should().Be(2);
        native.RouteAbsenceVerificationCalls.Should().Be(2);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        var json = await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None);
        using var document = JsonDocument.Parse(json!);
        document.RootElement.GetProperty("State").GetString().Should().Be("Completed");
        document.RootElement.GetProperty("OwnedCleanupCompleted").GetBoolean().Should().BeTrue();
        document.RootElement.GetProperty("OwnedTunnelName").ValueKind.Should().Be(JsonValueKind.Null);
        document.RootElement.GetProperty("OwnedTempConfigPath").ValueKind.Should().Be(JsonValueKind.Null);
        document.RootElement.GetProperty("OwnedRouteAddress").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task ExistingOwnedRoute_AfterDeleteFailureBlocksOriginalRestart()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            TraceOutput = "loc=GB\n",
            RouteDeleteFailure = new IOException("synthetic route delete failure")
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        native.RouteAddress.Should().Be("1.1.1.1/32");

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.RouteAbsenceVerificationCalls.Should().BeGreaterThan(0);
        native.StartedServices.Should().BeEmpty();
        native.Services.Single().IsRunning.Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task RouteAbsenceVerificationFailure_BlocksCleanupCompletionAndOriginalRestart()
    {
        var native = new FakeConfigCheckNative
        {
            HandshakeOutput = FreshHandshake(CandidateKey),
            TraceOutput = "loc=GB\n",
            RouteAbsenceVerificationFailure = new IOException("synthetic route verification failure")
        };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        await FluentActions.Awaiting(() => adapter.TestAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        native.RouteAddress.Should().BeNull();

        await FluentActions.Awaiting(() => adapter.RestoreAsync(session, CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        native.RouteAbsenceVerificationCalls.Should().BeGreaterThan(0);
        native.StartedServices.Should().BeEmpty();
        native.Services.Single().IsRunning.Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task PartialInitialStageWrite_IsRecoveredWithoutLeftoversOrFalseCompletion()
    {
        var native = new FakeConfigCheckNative { PartialInitialStageWriteFailure = true };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);

        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var stagedPath = native.LastStagedPath;
        File.Exists(stagedPath).Should().BeTrue();

        await adapter.RecoverAsync(config, CancellationToken.None);

        (await native.ReadSourceFileAsync(config.Path, CancellationToken.None)).Bytes.Should().Equal(config.Bytes);
        File.Exists(stagedPath).Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task InterruptedRecoveryStage_RetryRemovesOnlyExactOwnedStaleStage()
    {
        var native = new FakeConfigCheckNative();
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.BeforeReplace = (_, source, _) => File.Delete(source);
        native.ReplaceFailure = new IOException("synthetic interrupted replacement");
        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var initialStage = native.LastStagedPath!;
        native.PartialRecoveryStageWriteFailure = true;

        await FluentActions.Awaiting(() => adapter.RecoverAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var recoveryStage = native.LastStagedPath!;
        recoveryStage.Should().EndWith(".recovery.tmp");
        File.Exists(recoveryStage).Should().BeTrue();
        var unknownPath = Path.Combine(root, ".GB.conf.unknown.recovery.tmp");
        File.WriteAllBytes(unknownPath, [9, 8, 7]);
        native.PartialRecoveryStageWriteFailure = false;

        await adapter.RecoverAsync(config, CancellationToken.None);

        (await native.ReadSourceFileAsync(config.Path, CancellationToken.None)).Bytes.Should().Equal(config.Bytes);
        File.Exists(initialStage).Should().BeFalse();
        File.Exists(recoveryStage).Should().BeFalse();
        File.ReadAllBytes(unknownPath).Should().Equal([9, 8, 7]);
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task RecoverAll_FreshProcessRestoresMissingSourceAfterInterruptedReplacementAndStoppedService()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        native.BeforeReplace = (_, source, _) => File.Delete(source);
        native.ReplaceFailure = new IOException("synthetic interrupted replacement");
        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        File.Exists(config.Path).Should().BeFalse();
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        var recovered = await freshAdapter.RecoverAllAsync(CancellationToken.None);

        recovered.Single().SourcePath.Should().Be(config.Path);
        recovered.Single().OriginalServiceWasRunning.Should().BeTrue();
        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");

        var skipped = await freshAdapter.RecoverAllAsync(CancellationToken.None);
        skipped.Should().BeEmpty("completed journals are idempotently skipped without requiring a derived callback");
        native.StartedServices.Should().HaveCount(1);
    }

    [Fact]
    public async Task RecoverAll_FreshProcessDoesNotRequireCurrentlyParseableSourceForStoppedServiceRestore()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        File.WriteAllBytes(config.Path, [0xff, 0x00, 0x01, 0x02]);
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        var recovered = await freshAdapter.RecoverAllAsync(CancellationToken.None);

        recovered.Single().SourcePath.Should().Be(config.Path);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task RecoverAll_FreshProcessReconcilesDerivedConfigBeforeRestartingRecordedService()
    {
        var derivedPath = global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.EnsureSanitizedConfigFile(
            config.Path,
            Path.Combine(appDataRoot, "derived-confs"));
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await adapter.BeginAsync(config, CancellationToken.None, derivedPath);
        await adapter.StopOriginalAsync(session, CancellationToken.None);
        await adapter.CommitAsync(session, config, candidate, CancellationToken.None);
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        var recovered = await freshAdapter.RecoverAllAsync(
            CancellationToken.None,
            (context, _) =>
            {
                native.StartedServices.Should().BeEmpty();
                global::WireguardSplitTunnel.Core.Services.WireguardAllowedIpsSanitizer.ReconcileRepairedConfigFile(
                    context.SourcePath,
                    context.DerivedConfigPath,
                    context.SourceFingerprint);
                return Task.CompletedTask;
            });

        recovered.Single().OriginalServiceWasRunning.Should().BeTrue();
        CheckedConfig.Parse(derivedPath).PublicKey.Should().Be(CandidateKey);
        native.StartedServices.Should().Equal(native.Services[0].Name);
        (await freshAdapter.RecoverAllAsync(CancellationToken.None)).Should().BeEmpty();
    }

    [Fact]
    public async Task RecoverAll_FreshProcessRestoresInterruptedQuarantineWithoutParsingSource()
    {
        var native = new FakeConfigCheckNative
        {
            CrashBeforeRecycle = new IOException("synthetic crash before recycle")
        };
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var transaction = native.LastRecycleTransaction!;
        var privateRoot = Path.GetDirectoryName(transaction.OriginalBackupPath)!;
        File.Exists(config.Path).Should().BeFalse();
        native.RecoveryNative = CreateNativeForMutationTest();

        var recovered = await new WindowsConfigCheckAdapter(native, appDataRoot)
            .RecoverAllAsync(CancellationToken.None);

        recovered.Should().BeEmpty("an interrupted recycle has no original running service snapshot");
        File.ReadAllBytes(config.Path).Should().Equal(config.Bytes);
        File.Exists(transaction.QuarantinePath).Should().BeFalse();
        (await native.ReadJournalAsync(privateRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().Contain("\"Phase\":\"Completed\"");
    }

    [Fact]
    public async Task RecoverAll_AmbiguousChangedSourceBlocksRestartAndPreservesIncompleteJournal()
    {
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var unrelated = config.WithPeerServer(new ConfigCheckServer("uk6002.nordvpn.com", Key(64), "GB"));
        native.BeforeReplace = (_, source, _) => File.WriteAllBytes(source, unrelated);
        native.ReplaceFailure = new IOException("synthetic interruption after unrelated source appeared");
        await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, candidate, CancellationToken.None))
            .Should().ThrowAsync<IOException>();
        var freshAdapter = new WindowsConfigCheckAdapter(native, appDataRoot);

        await FluentActions.Awaiting(() => freshAdapter.RecoverAllAsync(CancellationToken.None))
            .Should().ThrowAsync<IOException>();

        File.ReadAllBytes(config.Path).Should().Equal(unrelated);
        native.StartedServices.Should().BeEmpty();
        native.Services.Single().IsRunning.Should().BeFalse();
        (await native.ReadJournalAsync(session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task Restore_SelectedServiceStartsBeforeSecondFailure_RoutesRestoreImmediatelyAndPrimaryFailureSurvives()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var routingGate = new SemaphoreSlim(1, 1);
        var native = new FakeConfigCheckNative();
        var first = OriginalService();
        var second = new ConfigCheckServiceState("WireGuardTunnel$US", "second-identity", true);
        native.Services.AddRange([first, second]);
        var primaryFailure = new IOException("second original service failed to start");
        native.StartFailure = service => service.Name == second.Name ? primaryFailure : null;
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var coordinator = new ConfigCheckCoordinator(softwareGate, routingGate, () => { });
        var routeRenewals = 0;
        var completionCount = 0;

        var actual = await Record.ExceptionAsync(() => coordinator.RunAsync(
            _ => Task.FromResult(true),
            token => ConfigCheckWorkflow.RunAsync(
                config,
                adapter,
                token,
                restoreRoutesAsync: routeToken =>
                {
                    routeToken.Should().Be(CancellationToken.None);
                    softwareGate.CurrentCount.Should().Be(0);
                    routingGate.CurrentCount.Should().Be(0);
                    native.StartedServices.Should().Equal(first.Name);
                    routeRenewals++;
                    return Task.CompletedTask;
                }),
            _ =>
            {
                completionCount++;
                return Task.CompletedTask;
            },
            _ => { },
            CancellationToken.None));

        actual.Should().BeSameAs(primaryFailure);
        routeRenewals.Should().Be(1);
        completionCount.Should().Be(0);
        native.StartedServices.Should().Equal(first.Name, second.Name);
        native.ObservedStartTokens.Should().HaveCount(2).And.OnlyContain(token => token == CancellationToken.None);
        native.Services.Single(service => service.Name == first.Name).IsRunning.Should().BeTrue();
        native.Services.Single(service => service.Name == second.Name).IsRunning.Should().BeFalse();
        var roots = await native.FindJournalRootsAsync(appDataRoot, CancellationToken.None);
        var journal = await native.ReadJournalAsync(
            roots.Should().ContainSingle().Subject,
            WindowsConfigCheckAdapter.SessionJournalName,
            CancellationToken.None);
        journal.Should().NotContain("\"State\":\"Completed\"");
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await routingGate.WaitAsync(0)).Should().BeTrue();
        routingGate.Release();
    }

    [Fact]
    public async Task Restore_RouteFailureThenServiceFailureAggregatesServicePrimaryFirst()
    {
        var native = new FakeConfigCheckNative();
        var first = OriginalService();
        var second = new ConfigCheckServiceState("WireGuardTunnel$US", "second-identity", true);
        native.Services.AddRange([first, second]);
        var serviceFailure = new IOException("second original service failed to start");
        var routeFailure = new InvalidOperationException("selected tunnel route renewal failed");
        native.StartFailure = service => service.Name == second.Name ? serviceFailure : null;
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var session = await BeginStopped(adapter);
        var routeAttempts = 0;

        var actual = await Record.ExceptionAsync(() => adapter.RestoreAsync(
            session,
            CancellationToken.None,
            serviceRestoredAsync: (_, _) =>
            {
                routeAttempts++;
                throw routeFailure;
            }));

        var aggregate = actual.Should().BeOfType<AggregateException>().Which;
        aggregate.InnerExceptions.Should().HaveCount(2);
        aggregate.InnerExceptions[0].Should().BeSameAs(serviceFailure);
        aggregate.InnerExceptions[1].Should().BeSameAs(routeFailure);
        routeAttempts.Should().Be(1, "a failed route renewal must not repeat within the same restore attempt");
        native.StartedServices.Should().Equal(first.Name, second.Name);
        (await native.ReadJournalAsync(
            session.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().NotContain("\"State\":\"Completed\"");
    }

    [Fact]
    public async Task Restore_RouteFailurePreventsCompletionAndPreservesOriginalException()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var routingGate = new SemaphoreSlim(1, 1);
        var native = new FakeConfigCheckNative();
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var coordinator = new ConfigCheckCoordinator(softwareGate, routingGate, () => { });
        var routeFailure = new IOException("selected tunnel route renewal failed");
        var routeRenewals = 0;
        var completionCount = 0;

        var actual = await Record.ExceptionAsync(() => coordinator.RunAsync(
            _ => Task.FromResult(true),
            token => ConfigCheckWorkflow.RunAsync(
                config,
                adapter,
                token,
                restoreRoutesAsync: routeToken =>
                {
                    routeToken.Should().Be(CancellationToken.None);
                    softwareGate.CurrentCount.Should().Be(0);
                    routingGate.CurrentCount.Should().Be(0);
                    routeRenewals++;
                    throw routeFailure;
                }),
            _ =>
            {
                completionCount++;
                return Task.CompletedTask;
            },
            _ => { },
            CancellationToken.None));

        actual.Should().BeSameAs(routeFailure);
        routeRenewals.Should().Be(1);
        completionCount.Should().Be(0);
        native.StartedServices.Should().Equal(OriginalService().Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        var roots = await native.FindJournalRootsAsync(appDataRoot, CancellationToken.None);
        var journal = await native.ReadJournalAsync(
            roots.Should().ContainSingle().Subject,
            WindowsConfigCheckAdapter.SessionJournalName,
            CancellationToken.None);
        journal.Should().NotContain("\"State\":\"Completed\"");
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await routingGate.WaitAsync(0)).Should().BeTrue();
        routingGate.Release();
    }

    [Fact]
    public async Task RecoverAll_FirstServiceRestoredBeforeLaterRecycleFailure_RenewsRoutesAndCompletesFirstSession()
    {
        using var softwareGate = new SemaphoreSlim(1, 1);
        using var routingGate = new SemaphoreSlim(1, 1);
        var recycleFailure = new IOException("synthetic crash before recycle");
        var native = new FakeConfigCheckNative { CrashBeforeRecycle = recycleFailure };
        native.Services.Add(OriginalService());
        var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
        var firstSession = await BeginStopped(adapter);
        var firstJournal = JsonNode.Parse((await native.ReadJournalAsync(
            firstSession.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))!)!.AsObject();
        firstJournal["State"] = "Completed";
        native.SetJournal(
            firstSession.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, firstJournal.ToJsonString());

        var secondConfig = CreateConfig(Path.Combine(root, "second.conf"));
        await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(secondConfig, CancellationToken.None))
            .Should().ThrowAsync<IOException>().Where(exception => ReferenceEquals(exception, recycleFailure));
        var recycleTransaction = native.LastRecycleTransaction!;
        var recycleRoot = Path.GetDirectoryName(recycleTransaction.OriginalBackupPath)!;
        firstJournal["State"] = "StopRequested";
        native.SetJournal(
            firstSession.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, firstJournal.ToJsonString());
        File.WriteAllBytes(secondConfig.Path, secondConfig.WithPeerServer(candidate));
        native.RecoveryNative = CreateNativeForMutationTest();
        var startupCoordinator = new ConfigCheckStartupRecoveryCoordinator(softwareGate, routingGate);
        var routeRenewals = 0;

        var actual = await Record.ExceptionAsync(() => startupCoordinator.RunAsync(
            new WindowsConfigCheckAdapter(native, appDataRoot),
            (_, _) => Task.CompletedTask,
            service => service.SourcePath == config.Path,
            routeToken =>
            {
                routeToken.Should().Be(CancellationToken.None);
                softwareGate.CurrentCount.Should().Be(0);
                routingGate.CurrentCount.Should().Be(0);
                native.StartedServices.Should().Equal(OriginalService().Name);
                routeRenewals++;
                return Task.CompletedTask;
            },
            CancellationToken.None));

        actual.Should().BeOfType<IOException>();
        routeRenewals.Should().Be(1);
        native.StartedServices.Should().Equal(OriginalService().Name);
        native.Services.Single().IsRunning.Should().BeTrue();
        (await native.ReadJournalAsync(
            firstSession.PrivateRoot, WindowsConfigCheckAdapter.SessionJournalName, CancellationToken.None))
            .Should().Contain("\"State\":\"Completed\"");
        (await native.ReadJournalAsync(
            recycleRoot, WindowsConfigCheckAdapter.RecycleJournalName, CancellationToken.None))
            .Should().NotContain("\"Phase\":\"Completed\"");
        File.ReadAllBytes(secondConfig.Path).Should().Equal(secondConfig.WithPeerServer(candidate));
        File.ReadAllBytes(recycleTransaction.QuarantinePath).Should().Equal(secondConfig.Bytes);
        (await softwareGate.WaitAsync(0)).Should().BeTrue();
        softwareGate.Release();
        (await routingGate.WaitAsync(0)).Should().BeTrue();
        routingGate.Release();
    }

    private async Task<IConfigCheckSession> BeginStopped(WindowsConfigCheckAdapter adapter, CancellationToken token = default)
    {
        var session = await adapter.BeginAsync(config, token);
        await adapter.StopOriginalAsync(session, token);
        return session;
    }

    private static ConfigCheckServiceState OriginalService() =>
        new("WireGuardTunnel$GB", "original-identity", true);

    private static string FreshHandshake(string key) => key + "\t" + (DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 10) + "\n";

    private static CheckedConfig CreateConfig(string path)
    {
        const string text = "[Interface]\r\n" +
            "PrivateKey = " + PrivateKey + "\r\n" +
            "Address = 10.5.0.2/32\r\n" +
            "DNS = 103.86.96.100\r\n" +
            "\r\n" +
            "[Peer]\r\n" +
            "PublicKey = " + PublicKey + " # retain comment\r\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\r\n" +
            "Endpoint = uk6000.nordvpn.com:51820 # retain comment\r\n";
        var encoding = new UTF8Encoding(false);
        var bytes = encoding.GetBytes(text);
        File.WriteAllBytes(path, bytes);
        return new CheckedConfig(
            path,
            "GB",
            text,
            bytes,
            encoding,
            [],
            CheckedConfig.FingerprintBytes(bytes),
            PrivateKey,
            PublicKey,
            "uk6000.nordvpn.com",
            51820,
            "GB",
            "10.5.0.2",
            "uk6000.nordvpn.com:51820");
    }

    private static string Key(int firstByte) => Convert.ToBase64String(
        Enumerable.Range(firstByte, 32).Select(value => (byte)value).ToArray());

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, true);
    }

    private sealed class FakeConfigCheckNative : IConfigCheckNative
    {
        private readonly Dictionary<string, string> journals = new(StringComparer.OrdinalIgnoreCase);

        public List<string> Events { get; } = [];
        public List<Uri> HttpUris { get; } = [];
        public List<string> DnsNames { get; } = [];
        public List<NativeProcessCall> ProcessCalls { get; } = [];
        public List<ConfigCheckServiceState> Services { get; } = [];
        public List<string> StoppedServices { get; } = [];
        public List<string> StartedServices { get; } = [];
        public List<CancellationToken> ObservedStartTokens { get; } = [];
        public List<string> RouteHistory { get; } = [];
        public List<string> PathAttributeChecks { get; } = [];
        public List<string?> ReplaceBackupPaths { get; } = [];
        public string CountriesJson { get; init; } = "[{\"id\":42,\"code\":\"GB\"}]";
        public string RecommendationsJson { get; init; } = """
        [{
          "status":"online",
          "hostname":"uk6001.nordvpn.com",
          "locations":[{"country":{"code":"GB"}}],
          "technologies":[{"identifier":"wireguard_udp","pivot":{"status":"online"},"metadata":[{"name":"public_key","value":"__CANDIDATE_KEY__"}]}]
        }]
        """.Replace("__CANDIDATE_KEY__", CandidateKey, StringComparison.Ordinal);
        public int InstallExitCode { get; init; }
        public string HandshakeOutput { get; init; } = string.Empty;
        public int CurlExitCode { get; init; }
        public string TraceOutput { get; init; } = "loc=GB\n";
        public string? ObservedCurlOutput { get; private set; }
        public string NativeErrorOutput { get; init; } = string.Empty;
        public bool DnsFailure { get; init; }
        public string? ActiveTunnelName { get; private set; }
        public string? LastOwnedTunnelName { get; private set; }
        public string? RouteAddress { get; private set; }
        public int RouteDeleteCalls { get; private set; }
        public int RouteAbsenceVerificationCalls { get; private set; }
        public int RecycleCalls { get; private set; }
        public string? RecycledPath { get; private set; }
        public ConfigCheckRecycleTransaction? LastRecycleTransaction { get; private set; }
        public int ReplaceCalls { get; private set; }
        public string? LastStagedPath { get; private set; }
        public IOException? ReplaceFailure { get; set; }
        public Func<ConfigCheckServiceState, IOException?>? StartFailure { get; set; }
        public WindowsConfigCheckNative? RecoveryNative { get; set; }
        public IOException? UninstallFailure { get; init; }
        public IOException? RecycleFailure { get; init; }
        public IOException? CrashBeforeRecycle { get; init; }
        public IOException? CrashAfterSinkBeforePhaseJournal { get; init; }
        public IOException? CrashAfterRecycledPhase { get; init; }
        public IOException? StagingDeleteFailure { get; set; }
        public bool PartialTempWriteFailure { get; init; }
        public bool AttemptJournalWriteFailure { get; init; }
        public IOException? CleanupCompletionJournalWriteFailure { get; set; }
        public IOException? RouteDeleteFailure { get; set; }
        public IOException? RouteAbsenceVerificationFailure { get; set; }
        public bool PartialInitialStageWriteFailure { get; init; }
        public bool PartialRecoveryStageWriteFailure { get; set; }
        public Action<string, string, string?>? BeforeReplace { get; set; }
        public Action<string>? BeforeRecycle { get; set; }
        public Func<ConfigCheckRecycleTransaction, Task>? BeforeRecycleMove { get; set; }
        public Func<string, bool>? SourceFileExistsOverride { get; set; }
        public int SourceFileExistsCalls { get; private set; }

        public Task<string> GetJsonAsync(Uri uri, CancellationToken token)
        {
            Events.Add("http:" + uri.AbsolutePath);
            HttpUris.Add(uri);
            return Task.FromResult(uri.AbsolutePath.Contains("countries", StringComparison.Ordinal) ? CountriesJson : RecommendationsJson);
        }

        public Task<IReadOnlyList<IPAddress>> ResolveAsync(string hostName, CancellationToken token)
        {
            Events.Add("dns:" + hostName);
            DnsNames.Add(hostName);
            if (DnsFailure) throw new IOException("synthetic DNS failure");
            IReadOnlyList<IPAddress> addresses = [IPAddress.Parse(hostName == "www.cloudflare.com" ? "1.1.1.1" : "192.0.2.10")];
            return Task.FromResult(addresses);
        }

        public Task<ConfigCheckNativeResult> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken token)
        {
            ProcessCalls.Add(new NativeProcessCall(fileName, arguments.ToArray()));
            if (fileName == "wireguard.exe")
            {
                Events.Add("install");
                LastOwnedTunnelName = Path.GetFileNameWithoutExtension(arguments[1]);
                ActiveTunnelName = InstallExitCode == 0 ? LastOwnedTunnelName : null;
                return Task.FromResult(new ConfigCheckNativeResult(InstallExitCode, NativeErrorOutput));
            }
            if (fileName == "wg.exe")
            {
                Events.Add("handshake");
                return Task.FromResult(new ConfigCheckNativeResult(0, HandshakeOutput));
            }
            if (fileName == "curl.exe")
            {
                Events.Add("curl");
                ObservedCurlOutput = CurlExitCode == 0 ? TraceOutput : NativeErrorOutput;
                return Task.FromResult(new ConfigCheckNativeResult(CurlExitCode, ObservedCurlOutput));
            }
            throw new InvalidOperationException("Unexpected synthetic process.");
        }

        public Task<IReadOnlyList<ConfigCheckServiceState>> GetTunnelServicesAsync(CancellationToken token)
        {
            Events.Add("service-snapshot");
            IReadOnlyList<ConfigCheckServiceState> snapshot = Services
                .Where(service => service.Name.StartsWith("WireGuardTunnel$", StringComparison.OrdinalIgnoreCase))
                .Select(service => service with
                {
                    Identity = CheckedConfig.FingerprintBytes(Encoding.UTF8.GetBytes(service.Identity))
                })
                .ToArray();
            return Task.FromResult(snapshot);
        }

        public Task StopServiceAsync(ConfigCheckServiceState service, CancellationToken token)
        {
            Events.Add("service-stop");
            StoppedServices.Add(service.Name);
            var index = Services.FindIndex(item => item.Name == service.Name);
            Services[index] = Services[index] with { IsRunning = false, Status = ConfigCheckServiceStatus.Stopped };
            return Task.CompletedTask;
        }

        public Task StartServiceAsync(ConfigCheckServiceState service, CancellationToken token)
        {
            Events.Add("service-start");
            StartedServices.Add(service.Name);
            ObservedStartTokens.Add(token);
            if (StartFailure?.Invoke(service) is { } failure) throw failure;
            var index = Services.FindIndex(item => item.Name == service.Name);
            Services[index] = Services[index] with { IsRunning = true, Status = ConfigCheckServiceStatus.Running };
            return Task.CompletedTask;
        }

        public Task DeleteTunnelServiceAsync(string tunnelName, CancellationToken token)
        {
            Events.Add("delete-tunnel");
            if (UninstallFailure is not null) throw UninstallFailure;
            ActiveTunnelName = null;
            return Task.CompletedTask;
        }

        public Task AddProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token)
        {
            Events.Add("route-add");
            RouteAddress = probeAddress + "/32";
            RouteHistory.Add(RouteAddress);
            return Task.CompletedTask;
        }

        public Task DeleteProbeRouteAsync(string tunnelName, IPAddress probeAddress, CancellationToken token)
        {
            Events.Add("route-delete");
            RouteDeleteCalls++;
            if (RouteDeleteFailure is not null) throw RouteDeleteFailure;
            if (RouteAddress != probeAddress + "/32")
                throw new IOException("synthetic route is absent");
            RouteAddress = null;
            return Task.CompletedTask;
        }

        public Task VerifyProbeRouteAbsentAsync(string tunnelName, IPAddress probeAddress, CancellationToken token)
        {
            Events.Add("verify-route-absent");
            RouteAbsenceVerificationCalls++;
            if (RouteAbsenceVerificationFailure is not null) throw RouteAbsenceVerificationFailure;
            if (RouteAddress == probeAddress + "/32")
                throw new IOException("synthetic owned route remains");
            return Task.CompletedTask;
        }

        public Task CreatePrivateDirectoryAsync(string path, CancellationToken token)
        {
            Events.Add("create-private");
            Directory.CreateDirectory(path);
            return Task.CompletedTask;
        }

        public Task WritePrivateFileAsync(string path, byte[] bytes, CancellationToken token)
        {
            if (Path.GetFileName(path) == "original.bin") Events.Add("backup");
            else if (Path.GetFileName(path) == "displaced.bin") Events.Add("write-displaced");
            else if (Path.GetExtension(path) == ".conf") Events.Add("write-temp");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            if (PartialTempWriteFailure && Path.GetExtension(path) == ".conf")
            {
                File.WriteAllBytes(path, bytes[..Math.Min(16, bytes.Length)]);
                throw new IOException("synthetic partial temp write");
            }
            File.WriteAllBytes(path, bytes);
            return Task.CompletedTask;
        }

        public Task<byte[]> ReadPrivateFileAsync(string path, CancellationToken token) => Task.FromResult(File.ReadAllBytes(path));

        public Task DeletePrivateFileAsync(string path, CancellationToken token)
        {
            Events.Add("delete-temp");
            File.Delete(path);
            return Task.CompletedTask;
        }

        public void EnsureNoReparsePoints(string path)
        {
            PathAttributeChecks.Add(Path.GetFullPath(path));
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(path);
        }

        public Task DeleteStagedFileAsync(string path, CancellationToken token)
        {
            Events.Add("delete-stage");
            if (StagingDeleteFailure is not null) throw StagingDeleteFailure;
            File.Delete(path);
            return Task.CompletedTask;
        }

        public Task VerifyStagedFileAbsentAsync(string path, CancellationToken token)
        {
            Events.Add("verify-stage-absent");
            if (File.Exists(path)) throw new IOException("synthetic staging file remains");
            return Task.CompletedTask;
        }

        public Task<bool> SourceFileExistsAsync(string path, CancellationToken token)
        {
            Events.Add("source-exists");
            SourceFileExistsCalls++;
            return Task.FromResult(SourceFileExistsOverride?.Invoke(path) ?? File.Exists(path));
        }

        public Task<ConfigCheckSourceFile> ReadSourceFileAsync(string path, CancellationToken token)
        {
            Events.Add("read-source");
            var fullPath = Path.GetFullPath(path);
            if (!string.Equals(Path.GetExtension(fullPath), ".conf", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Only plaintext .conf files are supported.");
            WindowsConfigCheckPrimitives.EnsureNoReparsePoints(fullPath);
            using var stream = OpenIdentityStream(fullPath);
            var bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
            return Task.FromResult(new ConfigCheckSourceFile(fullPath, bytes, GetOpenedIdentity(stream)));
        }

        public Task<ConfigCheckFileIdentity> StageReplacementAsync(
            string sourcePath, string stagedPath, byte[] bytes, CancellationToken token)
        {
            Events.Add("stage");
            LastStagedPath = stagedPath;
            var partial = (PartialInitialStageWriteFailure && stagedPath.EndsWith(".wgst.tmp", StringComparison.Ordinal)) ||
                (PartialRecoveryStageWriteFailure && stagedPath.EndsWith(".recovery.tmp", StringComparison.Ordinal));
            using (var stream = new FileStream(stagedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(bytes, 0, partial ? Math.Min(16, bytes.Length) : bytes.Length);
                if (partial) throw new IOException("synthetic partial staging write");
                return Task.FromResult(GetOpenedIdentity(stream));
            }
        }

        public async Task AtomicReplaceAsync(
            ConfigCheckReplacementTransaction transaction,
            Func<ConfigCheckReplacementProgress, Task> progressAsync,
            CancellationToken token)
        {
            Events.Add("replace");
            ReplaceCalls++;
            ReplaceBackupPaths.Add(transaction.ReplacementBackupPath);
            BeforeReplace?.Invoke(transaction.StagedPath, transaction.SourcePath, transaction.ReplacementBackupPath);
            var replaceFailure = ReplaceFailure;
            ReplaceFailure = null;
            if (replaceFailure is not null)
            {
                if (File.Exists(transaction.ReplacementBackupPath))
                {
                    using var backup = OpenIdentityStream(transaction.ReplacementBackupPath);
                    await progressAsync(new ConfigCheckReplacementProgress(
                        ConfigCheckReplacementPhase.Replaced, GetOpenedIdentity(backup)));
                }
                throw replaceFailure;
            }
            using (var stream = OpenIdentityStream(transaction.SourcePath))
            {
                if (GetOpenedIdentity(stream) != transaction.SourceIdentity)
                    throw new IOException("synthetic source identity changed before replacement");
            }
            File.Copy(transaction.StagedPath, transaction.SourcePath, overwrite: true);
            File.Delete(transaction.StagedPath);
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.Replaced, transaction.SourceIdentity));
            await progressAsync(new ConfigCheckReplacementProgress(
                ConfigCheckReplacementPhase.Cleaned, transaction.SourceIdentity));
        }

        public Task MoveStagedFileToMissingSourceAsync(string stagedPath, string sourcePath, CancellationToken token)
        {
            if (File.Exists(sourcePath)) throw new IOException("synthetic recovery destination appeared");
            File.Move(stagedPath, sourcePath);
            return Task.CompletedTask;
        }

        public async Task<ConfigCheckReplacementOutcome> RecoverReplacementAsync(
            ConfigCheckReplacementTransaction transaction,
            ConfigCheckFileIdentity? displacedSourceIdentity,
            Func<ConfigCheckReplacementProgress, Task> progressAsync,
            CancellationToken token)
        {
            if (RecoveryNative is not null)
                return await RecoveryNative.RecoverReplacementAsync(
                    transaction, displacedSourceIdentity, progressAsync, token);
            if (!File.Exists(transaction.SourcePath)) return ConfigCheckReplacementOutcome.SourceMissing;
            var fingerprint = CheckedConfig.FingerprintBytes(File.ReadAllBytes(transaction.SourcePath));
            if (fingerprint == transaction.ReplacementFingerprint)
            {
                await progressAsync(new ConfigCheckReplacementProgress(ConfigCheckReplacementPhase.Cleaned));
                return ConfigCheckReplacementOutcome.ReplacementApplied;
            }
            if (fingerprint == transaction.SourceFingerprint) return ConfigCheckReplacementOutcome.OriginalRetained;
            return ConfigCheckReplacementOutcome.NewerSourceRetained;
        }

        public Task<string?> ReadJournalAsync(string privateRoot, string journalName, CancellationToken token)
        {
            journals.TryGetValue(JournalKey(privateRoot, journalName), out var json);
            return Task.FromResult(json);
        }

        public Task WriteJournalAsync(string privateRoot, string journalName, string json, CancellationToken token)
        {
            Events.Add(journalName == WindowsConfigCheckAdapter.AttemptJournalName ? "journal-write-attempt" : "journal-write");
            if (AttemptJournalWriteFailure && journalName == WindowsConfigCheckAdapter.AttemptJournalName)
                throw new IOException("synthetic attempt journal write failure");
            if (CleanupCompletionJournalWriteFailure is not null &&
                journalName == WindowsConfigCheckAdapter.SessionJournalName &&
                json.Contains("\"OwnedCleanupCompleted\":true", StringComparison.Ordinal))
                throw CleanupCompletionJournalWriteFailure;
            journals[JournalKey(privateRoot, journalName)] = json;
            return Task.CompletedTask;
        }

        public Task ClearAttemptJournalAsync(string privateRoot, CancellationToken token)
        {
            Events.Add("journal-clear");
            journals.Remove(JournalKey(privateRoot, WindowsConfigCheckAdapter.AttemptJournalName));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<string>> FindJournalRootsAsync(string dataRoot, CancellationToken token)
        {
            IReadOnlyList<string> roots = journals.Keys
                .Where(key =>
                    key.EndsWith("|" + WindowsConfigCheckAdapter.SessionJournalName, StringComparison.Ordinal) ||
                    key.EndsWith("|" + WindowsConfigCheckAdapter.RecycleJournalName, StringComparison.Ordinal))
                .Select(key => key[..key.LastIndexOf('|')])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return Task.FromResult(roots);
        }

        public Task VerifyTunnelInactiveAsync(string tunnelName, CancellationToken token)
        {
            Events.Add("verify-inactive");
            if (ActiveTunnelName is not null) throw new IOException("synthetic tunnel still active");
            return Task.CompletedTask;
        }

        public async Task RecycleFileAsync(
            ConfigCheckRecycleTransaction transaction,
            Func<ConfigCheckRecycleProgress, Task> progressAsync,
            CancellationToken token)
        {
            Events.Add("recycle");
            RecycleCalls++;
            LastRecycleTransaction = transaction;
            RecycledPath = transaction.SourcePath;
            BeforeRecycle?.Invoke(transaction.SourcePath);
            using (var stream = OpenIdentityStream(transaction.SourcePath))
            {
                if (GetOpenedIdentity(stream) != transaction.SourceIdentity)
                    throw new IOException("synthetic source identity changed before recycle");
            }
            if (BeforeRecycleMove is not null) await BeforeRecycleMove(transaction);
            Directory.CreateDirectory(transaction.QuarantineDirectory);
            File.Move(transaction.SourcePath, transaction.QuarantinePath);
            await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Quarantined));
            if (CrashBeforeRecycle is not null) throw CrashBeforeRecycle;
            if (RecycleFailure is not null)
            {
                File.Move(transaction.QuarantinePath, transaction.SourcePath);
                Directory.Delete(transaction.QuarantineDirectory);
                throw RecycleFailure;
            }
            File.Delete(transaction.QuarantinePath);
            if (CrashAfterSinkBeforePhaseJournal is not null) throw CrashAfterSinkBeforePhaseJournal;
            await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Recycled));
            if (CrashAfterRecycledPhase is not null) throw CrashAfterRecycledPhase;
            Directory.Delete(transaction.QuarantineDirectory);
            await progressAsync(new ConfigCheckRecycleProgress(ConfigCheckRecyclePhase.Completed));
        }

        public Task RecoverRecycleAsync(
            ConfigCheckRecycleTransaction transaction,
            ConfigCheckRecyclePhase phase,
            Func<ConfigCheckRecycleProgress, Task> progressAsync,
            CancellationToken token) =>
            RecoveryNative is null
                ? throw new InvalidOperationException("A recovery native is required for recycle recovery.")
                : RecoveryNative.RecoverRecycleAsync(transaction, phase, progressAsync, token);

        public Task DelayAsync(TimeSpan delay, CancellationToken token) => Task.CompletedTask;

        public string JournalTexts(string privateRoot) => string.Join("\n", journals
            .Where(pair => pair.Key.StartsWith(privateRoot + "|", StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair.Value));

        public void SetJournal(string privateRoot, string journalName, string json) =>
            journals[JournalKey(privateRoot, journalName)] = json;

        private static FileStream OpenIdentityStream(string path) => new(
            path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete, 4096, FileOptions.SequentialScan);

        private static ConfigCheckFileIdentity GetOpenedIdentity(FileStream stream)
        {
            var identity = ConfigCheckParser.GetOpenedIdentity(stream);
            return new ConfigCheckFileIdentity(identity.VolumeSerialNumber, identity.FileIndex);
        }

        private static string JournalKey(string privateRoot, string journalName) => privateRoot + "|" + journalName;
    }

    private sealed class FakeProcessFactory(DelayedFakeProcess process) : IConfigCheckProcessFactory
    {
        public List<System.Diagnostics.ProcessStartInfo> StartInfos { get; } = [];
        public IConfigCheckProcess Start(System.Diagnostics.ProcessStartInfo startInfo)
        {
            StartInfos.Add(startInfo);
            return process;
        }
    }

    private sealed class ScriptedProcessFactory(
        Func<IReadOnlyList<string>, ConfigCheckNativeResult> handler) : IConfigCheckProcessFactory
    {
        public List<string[]> Calls { get; } = [];

        public IConfigCheckProcess Start(System.Diagnostics.ProcessStartInfo startInfo)
        {
            var arguments = startInfo.ArgumentList.ToArray();
            Calls.Add(arguments);
            return new CompletedFakeProcess(handler(arguments));
        }
    }

    private sealed class CompletedFakeProcess(ConfigCheckNativeResult result) : IConfigCheckProcess
    {
        public bool HasExited => true;
        public int ExitCode => result.ExitCode;
        public void Kill(bool entireProcessTree) { }
        public Task WaitForExitAsync(CancellationToken token) => Task.CompletedTask;
        public Task<string> ReadStandardOutputAsync(CancellationToken token) => Task.FromResult(result.Output);
        public Task<string> ReadStandardErrorAsync(CancellationToken token) => Task.FromResult(result.Output);
        public void Dispose() { }
    }

    private sealed class DelayedFakeProcess : IConfigCheckProcess
    {
        private readonly string marker;
        private int killed;

        public DelayedFakeProcess(string marker)
        {
            this.marker = marker;
            _ = RunDelayedMutation();
        }

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool KillCalled => killed != 0;
        public bool EntireProcessTree { get; private set; }
        public bool Mutated { get; private set; }
        public bool HasExited => Completion.Task.IsCompleted;
        public int ExitCode => KillCalled ? -1 : 0;
        public void Kill(bool entireProcessTree)
        {
            EntireProcessTree = entireProcessTree;
            if (Interlocked.Exchange(ref killed, 1) == 0) Completion.TrySetResult();
        }
        public Task WaitForExitAsync(CancellationToken token) => Completion.Task.WaitAsync(token);
        public Task<string> ReadStandardOutputAsync(CancellationToken token) => Task.FromResult(string.Empty);
        public Task<string> ReadStandardErrorAsync(CancellationToken token) => Task.FromResult(string.Empty);
        public void Dispose() { }

        private async Task RunDelayedMutation()
        {
            Started.TrySetResult();
            await Task.Delay(100);
            if (!KillCalled)
            {
                await File.WriteAllBytesAsync(marker, [1]);
                Mutated = true;
            }
            Completion.TrySetResult();
        }
    }

    private sealed record NativeProcessCall(string FileName, string[] Arguments);
}
