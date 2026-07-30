using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using FluentAssertions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class LauncherScriptTests : IDisposable
{
    private readonly LauncherScriptFixture _fixture = new();

    [Fact]
    public void NoProtectedTransaction_ContinuesNormalLaunchAndIgnoresLocalStagedState()
    {
        File.WriteAllText(
            Path.Combine(_fixture.ProtectedRoot, "local-update.json"),
            """{"phase":"LocalStaged","transactionId":"ffffffffffffffffffffffffffffffff"}""");

        var result = _fixture.InvokeRecoveryWithoutPointer();

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeFalse();
        result.Result.Blocked.Should().BeFalse();
        result.Result.ExitCode.Should().Be(0);
        result.Result.Message.Should().Be("ContinueNormalLaunch");
        File.Exists(_fixture.InvocationPath).Should().BeFalse();
    }

    [Fact]
    public void ProtectedStaged_ContinuesCurrentVersionWithoutInvokingHelper()
    {
        _fixture.CreateProtectedTransaction("ProtectedStaged");

        var result = _fixture.InvokeRecovery(helperExitCode: 10);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeFalse();
        result.Result.Blocked.Should().BeFalse();
        result.Result.Message.Should().Be("ContinueNormalLaunch");
        File.Exists(_fixture.InvocationPath).Should().BeFalse();
    }

    [Fact]
    public void CloseAuthorized_InvokesOnlyRecomputedProtectedHelperWithExactArguments()
    {
        var transaction = _fixture.CreateProtectedTransaction("CloseAuthorized");

        var result = _fixture.InvokeRecovery(helperExitCode: 10);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeTrue();
        result.Result.Blocked.Should().BeFalse();
        result.Result.ExitCode.Should().Be(10);
        var invocation = _fixture.ReadInvocation();
        invocation.FilePath.Should().Be(transaction.HelperPath);
        invocation.Arguments.Should().Equal(
            "--mode",
            "recover-and-launch",
            "--transaction",
            transaction.RecordPath);
    }

    [Theory]
    [InlineData("Applying")]
    [InlineData("AppliedAwaitingHealth")]
    [InlineData("Prepared")]
    [InlineData("BackingUp")]
    [InlineData("RollingBack")]
    [InlineData("Committed")]
    [InlineData("RolledBack")]
    public void ApplyAndRecoveryPhases_InvokeRecoverAndLaunch(string phase)
    {
        _fixture.CreateProtectedTransaction(phase);

        var result = _fixture.InvokeRecovery(helperExitCode: 0);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeFalse();
        result.Result.Blocked.Should().BeFalse();
        _fixture.ReadInvocation().Arguments.Should().ContainInOrder(
            "--mode",
            "recover-and-launch",
            "--transaction");
    }

    [Fact]
    public void RecoveryBlocked_ReturnsRepairGuidanceWithoutInvokingHelper()
    {
        _fixture.CreateProtectedTransaction("RecoveryBlocked");

        var result = _fixture.InvokeRecovery(helperExitCode: 0);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeFalse();
        result.Result.Blocked.Should().BeTrue();
        result.Result.ExitCode.Should().NotBe(0);
        result.Result.Message.Should().Contain("RepairBlockedUpdate");
        result.Result.Message.Should().Contain("updater.log");
        File.Exists(_fixture.InvocationPath).Should().BeFalse();
    }

    [Theory]
    [InlineData(10)]
    [InlineData(20)]
    public void HelperHandledExitCodes_StopASecondLaunch(int helperExitCode)
    {
        _fixture.CreateProtectedTransaction("CloseAuthorized");

        var result = _fixture.InvokeRecovery(helperExitCode);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Handled.Should().BeTrue();
        result.Result.Blocked.Should().BeFalse();
        result.Result.ExitCode.Should().Be(helperExitCode);
    }

    [Theory]
    [InlineData("acl")]
    [InlineData("hash")]
    [InlineData("productVersion")]
    public void ProtectedHelperSecurityMismatch_BlocksBeforeProcessCreation(
        string mismatch)
    {
        var transaction = _fixture.CreateProtectedTransaction(
            "CloseAuthorized");
        if (mismatch == "hash")
        {
            File.AppendAllText(transaction.HelperPath, "tamper");
        }

        var result = _fixture.InvokeRecovery(
            helperExitCode: 10,
            aclValid: mismatch != "acl",
            productVersion: mismatch == "productVersion"
                ? "9.9.9"
                : _fixture.Version);

        result.Process.ExitCode.Should().Be(0, result.Process.CombinedOutput);
        result.Result.Blocked.Should().BeTrue();
        result.Result.ExitCode.Should().NotBe(0);
        File.Exists(_fixture.InvocationPath).Should().BeFalse();
    }

    [Fact]
    public void UacCancellation_DoesNotInvokeRecoveryOrChangeProtectedPhase()
    {
        var transaction = _fixture.CreateProtectedTransaction(
            "CloseAuthorized");
        var before = File.ReadAllBytes(transaction.RecordPath);

        var result = _fixture.InvokeStartupGate(
            isAdministrator: false,
            alreadyElevated: false,
            dryRun: false,
            postInstallSelfTest: false,
            cancelElevation: true);

        result.ExitCode.Should().NotBe(0);
        File.Exists(_fixture.GateRecoveryMarkerPath).Should().BeFalse();
        File.ReadAllBytes(transaction.RecordPath).Should().Equal(before);
    }

    [Fact]
    public void ElevatedNormalRun_InvokesRecoveryGate()
    {
        var result = _fixture.InvokeStartupGate(
            isAdministrator: true,
            alreadyElevated: true,
            dryRun: false,
            postInstallSelfTest: false,
            cancelElevation: false);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("Recovery");
        File.Exists(_fixture.GateRecoveryMarkerPath).Should().BeTrue();
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DryRunAndPostInstallSelfTest_NeverInvokeUpdaterRecovery(
        bool dryRun,
        bool postInstallSelfTest)
    {
        var result = _fixture.InvokeStartupGate(
            isAdministrator: true,
            alreadyElevated: true,
            dryRun,
            postInstallSelfTest,
            cancelElevation: false);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be(
            "ContinueNormalLaunch");
        File.Exists(_fixture.GateRecoveryMarkerPath).Should().BeFalse();
    }

    [Fact]
    public void DryRun_SelectsCurrentExecutableWithoutMutationOrLaunchArguments()
    {
        var before = _fixture.SnapshotDryRunRepository();

        var result = _fixture.InvokeDryRun();

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be(
            $"exe {_fixture.DryRunExecutablePath}");
        result.CombinedOutput.Should().NotContain(
            "--update-transaction");
        result.CombinedOutput.Should().NotContain(
            "--update-version");
        _fixture.SnapshotDryRunRepository().Should().BeEquivalentTo(before);
    }

    [Fact]
    public void DryRun_RunsUnderPowerShellCoreWithoutCompatibilityRemoting()
    {
        var before = _fixture.SnapshotDryRunRepository();

        var result = _fixture.InvokeDryRunWithPowerShellCore();

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be(
            $"exe {_fixture.DryRunExecutablePath}");
        result.CombinedOutput.Should().NotContain("Export-PSSession");
        File.Exists(_fixture.CoreModuleHijackMarkerPath)
            .Should().BeFalse();
        _fixture.SnapshotDryRunRepository().Should().BeEquivalentTo(before);
    }

    [Fact]
    public void NormalLaunch_ResolvesExecutableOnlyAfterRecoveryGate()
    {
        var source = File.ReadAllText(
            Path.Combine(
                _fixture.RepositoryRoot,
                "scripts",
                "start.ps1"));
        var dryRun = source.IndexOf(
            "if ($DryRun)",
            StringComparison.Ordinal);
        var startupGate = source.IndexOf(
            "$startupGate = Invoke-WgstStartupGate",
            StringComparison.Ordinal);
        var recoveryResult = source.IndexOf(
            "if ($startupGate.Action -eq 'Recovery')",
            StringComparison.Ordinal);
        var normalResolution = source.IndexOf(
            "$appExe = Resolve-WgstAppExecutable",
            recoveryResult,
            StringComparison.Ordinal);

        dryRun.Should().BeGreaterThan(-1);
        startupGate.Should().BeGreaterThan(dryRun);
        recoveryResult.Should().BeGreaterThan(startupGate);
        normalResolution.Should().BeGreaterThan(recoveryResult);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExactProtectedSecurityDescriptor_AcceptsCanonicalDescriptor(
        bool directory)
    {
        var descriptor = CreateProtectedDescriptor(directory);

        var result = _fixture.InvokeDescriptorValidation(
            descriptor,
            directory);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("True");
    }

    [Fact]
    public void ExactProtectedSecurityDescriptor_RejectsWrongOwner()
    {
        var descriptor = CreateProtectedDescriptor(
            directory: true,
            owner: Administrators);

        var result = _fixture.InvokeDescriptorValidation(
            descriptor,
            directory: true);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("False");
    }

    [Fact]
    public void ExactProtectedSecurityDescriptor_RejectsExtraAce()
    {
        var descriptor = CreateProtectedDescriptor(
            directory: true,
            addExtraAce: true);

        var result = _fixture.InvokeDescriptorValidation(
            descriptor,
            directory: true);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("False");
    }

    [Fact]
    public void ExactProtectedSecurityDescriptor_RejectsCallbackAce()
    {
        var descriptor = CreateProtectedDescriptor(
            directory: false,
            callbackAdministratorAce: true);

        var result = _fixture.InvokeDescriptorValidation(
            descriptor,
            directory: false);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("False");
    }

    public void Dispose() => _fixture.Dispose();

    private static readonly SecurityIdentifier LocalSystem = new(
        WellKnownSidType.LocalSystemSid,
        null);

    private static readonly SecurityIdentifier Administrators = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);

    private static byte[] CreateProtectedDescriptor(
        bool directory,
        SecurityIdentifier? owner = null,
        bool addExtraAce = false,
        bool callbackAdministratorAce = false)
    {
        var flags = directory
            ? AceFlags.ContainerInherit | AceFlags.ObjectInherit
            : AceFlags.None;
        var acl = new RawAcl(
            GenericAcl.AclRevision,
            addExtraAce ? 3 : 2);
        acl.InsertAce(
            acl.Count,
            new CommonAce(
                flags,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                Administrators,
                callbackAdministratorAce,
                callbackAdministratorAce
                    ? [1, 2, 3, 4]
                    : null));
        acl.InsertAce(
            acl.Count,
            new CommonAce(
                flags,
                AceQualifier.AccessAllowed,
                (int)FileSystemRights.FullControl,
                LocalSystem,
                isCallback: false,
                opaque: null));
        if (addExtraAce)
        {
            acl.InsertAce(
                acl.Count,
                new CommonAce(
                    flags,
                    AceQualifier.AccessAllowed,
                    (int)FileSystemRights.FullControl,
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        null),
                    isCallback: false,
                    opaque: null));
        }

        var descriptor = new RawSecurityDescriptor(
            ControlFlags.DiscretionaryAclPresent
                | ControlFlags.DiscretionaryAclProtected,
            owner ?? LocalSystem,
            group: null,
            systemAcl: null,
            discretionaryAcl: acl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }
}

internal sealed class LauncherScriptFixture : IDisposable
{
    internal LauncherScriptFixture()
    {
        RepositoryRoot = FindRepositoryRoot();
        Root = Path.Combine(
            Path.GetTempPath(),
            "wgst-launcher-tests",
            Guid.NewGuid().ToString("N"));
        ProtectedRoot = Path.Combine(Root, "protected");
        TransactionsRoot = Path.Combine(
            ProtectedRoot,
            "UpdateTransactions");
        InvocationPath = Path.Combine(Root, "invocation.json");
        GateRecoveryMarkerPath = Path.Combine(
            Root,
            "gate-recovery.marker");
        Directory.CreateDirectory(TransactionsRoot);

        var testProcess = Path.Combine(
            AppContext.BaseDirectory,
            "WireguardSplitTunnel.TestProcess.exe");
        File.Exists(testProcess).Should().BeTrue();
        TestProcessPath = testProcess;
        Version = System.Diagnostics.FileVersionInfo
            .GetVersionInfo(testProcess)
            .ProductVersion!;

        DryRunRoot = Path.Combine(Root, "dry-run-repository");
        var scripts = Path.Combine(DryRunRoot, "scripts");
        Directory.CreateDirectory(scripts);
        File.Copy(
            Path.Combine(RepositoryRoot, "scripts", "start.ps1"),
            Path.Combine(scripts, "start.ps1"));
        Directory.CreateDirectory(
            Path.Combine(DryRunRoot, "WireguardSplitTunnel"));
        DryRunExecutablePath = Path.Combine(
            DryRunRoot,
            "WireguardSplitTunnel",
            "WireguardSplitTunnel.App.exe");
        File.Copy(testProcess, DryRunExecutablePath);
        File.WriteAllText(
            Path.Combine(DryRunRoot, "Directory.Build.props"),
            $"<Project><PropertyGroup><VersionPrefix>{Version}</VersionPrefix></PropertyGroup></Project>",
            new UTF8Encoding(false));

        PowerShellCoreMaliciousModulesPath = Path.Combine(
            Root,
            "pwsh-malicious-modules");
        var maliciousManagement = Path.Combine(
            PowerShellCoreMaliciousModulesPath,
            "Microsoft.PowerShell.Management");
        Directory.CreateDirectory(maliciousManagement);
        CoreModuleHijackMarkerPath = Path.Combine(
            Root,
            "pwsh-module-hijack.marker");
        File.WriteAllText(
            Path.Combine(
                maliciousManagement,
                "Microsoft.PowerShell.Management.psd1"),
            "@{ RootModule = 'Microsoft.PowerShell.Management.psm1'; "
            + "ModuleVersion = '1.0.0.0'; "
            + "GUID = '11111111-1111-1111-1111-111111111111' }",
            new UTF8Encoding(false));
        File.WriteAllText(
            Path.Combine(
                maliciousManagement,
                "Microsoft.PowerShell.Management.psm1"),
            $"[IO.File]::WriteAllText('{Escape(CoreModuleHijackMarkerPath)}', 'loaded')",
            new UTF8Encoding(false));
    }

    internal string RepositoryRoot { get; }
    internal string Root { get; }
    internal string ProtectedRoot { get; }
    internal string TransactionsRoot { get; }
    internal string InvocationPath { get; }
    internal string GateRecoveryMarkerPath { get; }
    internal string TestProcessPath { get; }
    internal string Version { get; }
    internal string DryRunRoot { get; }
    internal string DryRunExecutablePath { get; }
    internal string PowerShellCoreMaliciousModulesPath { get; }
    internal string CoreModuleHijackMarkerPath { get; }

    internal ProtectedTransactionFixture CreateProtectedTransaction(
        string phase)
    {
        const string transactionId =
            "00112233445566778899aabbccddeeff";
        var transactionRoot = Path.Combine(
            TransactionsRoot,
            transactionId);
        var helperRoot = Path.Combine(
            transactionRoot,
            "helper");
        Directory.CreateDirectory(helperRoot);
        var helperPath = Path.Combine(
            helperRoot,
            "WireguardSplitTunnel.Updater.exe");
        File.Copy(
            TestProcessPath,
            helperPath,
            overwrite: true);
        var helperHash = Convert.ToHexString(
                SHA256.HashData(
                    File.ReadAllBytes(helperPath)))
            .ToLowerInvariant();
        var recordPath = Path.Combine(
            transactionRoot,
            "transaction.json");
        var record = new
        {
            schemaVersion = 1,
            transactionId,
            version = Version,
            source = "Automatic",
            installedRelease = new { },
            candidate = new { },
            helperSha256 = helperHash,
            phase,
            authorizedProcess =
                phase == "CloseAuthorized"
                    ? new
                    {
                        processId = 123,
                        creationTimeFileTimeUtc = 456,
                        imagePath = @"C:\fixture\app.exe"
                    }
                    : null,
            journal = new { }
        };
        File.WriteAllText(
            recordPath,
            JsonSerializer.Serialize(record),
            new UTF8Encoding(false));
        File.WriteAllText(
            Path.Combine(
                TransactionsRoot,
                "active-transaction.json"),
            $$"""{"schemaVersion":1,"transactionId":"{{transactionId}}"}""",
            new UTF8Encoding(false));
        if (File.Exists(InvocationPath))
        {
            File.Delete(InvocationPath);
        }

        return new ProtectedTransactionFixture(
            transactionId,
            recordPath,
            helperPath);
    }

    internal RecoveryProcessResult InvokeRecoveryWithoutPointer()
    {
        var pointer = Path.Combine(
            TransactionsRoot,
            "active-transaction.json");
        if (File.Exists(pointer))
        {
            File.Delete(pointer);
        }

        return InvokeRecovery(helperExitCode: 10);
    }

    internal RecoveryProcessResult InvokeRecovery(
        int helperExitCode,
        bool aclValid = true,
        string? productVersion = null)
    {
        var scriptPath = Path.Combine(
            RepositoryRoot,
            "scripts",
            "update-launcher.ps1");
        var inline = $$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            $acl = { param($Path, [bool]$Directory) return {{Ps(aclValid)}} }
            $version = { param($Path) return '{{Escape(productVersion ?? Version)}}' }
            $process = {
                param($FilePath, $Arguments)
                [IO.File]::WriteAllText(
                    '{{Escape(InvocationPath)}}',
                    (@{
                        filePath = $FilePath
                        arguments = @($Arguments)
                    } | ConvertTo-Json -Compress),
                    [Text.UTF8Encoding]::new($false))
                return {{helperExitCode}}
            }
            $result = Invoke-WgstProtectedUpdateRecoveryCore `
                -ProtectedProductRoot '{{Escape(ProtectedRoot)}}' `
                -AclValidator $acl `
                -ProductVersionReader $version `
                -ProcessInvoker $process
            $result | ConvertTo-Json -Compress
            """;
        var process = RunInlinePowerShell(inline);
        var json = process.StandardOutput
            .Split(
                ['\r', '\n'],
                StringSplitOptions.RemoveEmptyEntries)
            .LastOrDefault() ?? "{}";
        var result = JsonSerializer.Deserialize<RecoveryResult>(
            json,
            new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new RecoveryResult(
                false,
                true,
                70,
                "invalid");
        return new RecoveryProcessResult(process, result);
    }

    internal ScriptProcessResult InvokeStartupGate(
        bool isAdministrator,
        bool alreadyElevated,
        bool dryRun,
        bool postInstallSelfTest,
        bool cancelElevation)
    {
        if (File.Exists(GateRecoveryMarkerPath))
        {
            File.Delete(GateRecoveryMarkerPath);
        }

        var scriptPath = Path.Combine(
            RepositoryRoot,
            "scripts",
            "start.ps1");
        var elevation = cancelElevation
            ? "throw 'uac_cancelled'"
            : "return $true";
        var inline = $$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            $elevation = { {{elevation}} }
            $recovery = {
                [IO.File]::WriteAllText(
                    '{{Escape(GateRecoveryMarkerPath)}}',
                    'called',
                    [Text.UTF8Encoding]::new($false))
                [pscustomobject]@{
                    Handled = $false
                    Blocked = $false
                    ExitCode = 0
                    Message = 'ContinueNormalLaunch'
                }
            }
            $gate = Invoke-WgstStartupGate `
                -DryRun:{{Ps(dryRun)}} `
                -PostInstallSelfTest:{{Ps(postInstallSelfTest)}} `
                -IsAdministrator:{{Ps(isAdministrator)}} `
                -AlreadyElevated:{{Ps(alreadyElevated)}} `
                -ElevationAction $elevation `
                -RecoveryAction $recovery
            $gate.Action
            """;
        return RunInlinePowerShell(inline);
    }

    internal ScriptProcessResult InvokeDryRun() =>
        ReleaseScriptFixture.RunPowerShell(
            Path.Combine(
                DryRunRoot,
                "scripts",
                "start.ps1"),
            ["-DryRun"]);

    internal ScriptProcessResult InvokeDryRunWithPowerShellCore()
    {
        var start = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "pwsh.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(
            Path.Combine(
                DryRunRoot,
                "scripts",
                "start.ps1"));
        start.ArgumentList.Add("-DryRun");
        start.Environment["PSModulePath"] =
            PowerShellCoreMaliciousModulesPath;

        using var process = System.Diagnostics.Process.Start(start);
        process.Should().NotBeNull();
        var stdout = process!.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(60_000).Should().BeTrue();
        return new ScriptProcessResult(
            process.ExitCode,
            stdout,
            stderr);
    }

    internal ScriptProcessResult InvokeDescriptorValidation(
        byte[] descriptor,
        bool directory)
    {
        var scriptPath = Path.Combine(
            RepositoryRoot,
            "scripts",
            "update-launcher.ps1");
        var encoded = Convert.ToBase64String(descriptor);
        var inline = $$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(scriptPath)}}' -LibraryOnly
            $descriptor = [Convert]::FromBase64String('{{encoded}}')
            Test-WgstExactProtectedSecurityDescriptor `
                -Descriptor $descriptor `
                -Directory:{{Ps(directory)}}
            """;
        return RunInlinePowerShell(inline);
    }

    internal IReadOnlyDictionary<string, string> SnapshotDryRunRepository() =>
        Directory.EnumerateFiles(
                DryRunRoot,
                "*",
                SearchOption.AllDirectories)
            .ToDictionary(
                path => Path.GetRelativePath(DryRunRoot, path),
                path => Convert.ToHexString(
                    SHA256.HashData(File.ReadAllBytes(path))),
                StringComparer.Ordinal);

    internal HelperInvocation ReadInvocation()
    {
        using var document = JsonDocument.Parse(
            File.ReadAllBytes(InvocationPath));
        return new HelperInvocation(
            document.RootElement
                .GetProperty("filePath")
                .GetString()!,
            document.RootElement
                .GetProperty("arguments")
                .EnumerateArray()
                .Select(item => item.GetString()!)
                .ToArray());
    }

    internal ScriptProcessResult RunInlinePowerShell(string source)
    {
        var path = Path.Combine(
            Root,
            $"inline-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(
            path,
            source,
            new UTF8Encoding(false));
        return ReleaseScriptFixture.RunPowerShell(path);
    }

    public void Dispose()
    {
        if (Directory.Exists(Root))
        {
            Directory.Delete(Root, recursive: true);
        }
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(
                    Path.Combine(
                        current.FullName,
                        "WireguardSplitTunnel.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new DirectoryNotFoundException(
            "Could not locate repository root.");
    }

    private static string Escape(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    private static string Ps(bool value) =>
        value ? "$true" : "$false";
}

internal sealed record ProtectedTransactionFixture(
    string TransactionId,
    string RecordPath,
    string HelperPath);

internal sealed record RecoveryResult(
    bool Handled,
    bool Blocked,
    int ExitCode,
    string Message);

internal sealed record RecoveryProcessResult(
    ScriptProcessResult Process,
    RecoveryResult Result);

internal sealed record HelperInvocation(
    string FilePath,
    IReadOnlyList<string> Arguments);
