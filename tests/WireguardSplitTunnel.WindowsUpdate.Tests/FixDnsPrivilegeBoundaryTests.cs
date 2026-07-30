using System.Text;
using System.Text.Json;
using FluentAssertions;

namespace WireguardSplitTunnel.WindowsUpdate.Tests;

public sealed class FixDnsPrivilegeBoundaryTests : IDisposable
{
    private readonly string repositoryRoot = FindRepositoryRoot();
    private readonly string root = Path.Combine(
        Path.GetTempPath(),
        "wgst-fix-dns-boundary-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void DefaultRequest_PrefersVerifiedActiveSgAndCarriesOnlyGuid()
    {
        var sgGuid = Guid.NewGuid();
        var otherGuid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $adapters = @(
                {{VerifiedAdapter("other-tunnel", otherGuid)}}
                {{VerifiedAdapter("SG", sgGuid)}}
            )
            $query = { @($adapters) }.GetNewClosure()
            New-WgstDefaultDnsRepairRequest `
                -AdapterQuery $query |
                ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var document = JsonDocument.Parse(
            result.StandardOutput.Trim());
        document.RootElement.TryGetProperty(
            "DnsServers",
            out _).Should().BeFalse();
        var request = JsonSerializer.Deserialize<RepairRequest>(
            result.StandardOutput.Trim(),
            JsonOptions);
        request.Should().NotBeNull();
        request!.InterfaceGuid.Should().Be(sgGuid.ToString("D"));
    }

    [Fact]
    public void DefaultRequest_CanonicalizesBraceFormSystemInterfaceGuid()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $adapter = [pscustomobject]@{
                Name = 'SG'
                Status = 'Up'
                InterfaceGuid = '{' + '{{guid:D}}' + '}'
                InterfaceIndex = 23
                InterfaceDescription = 'WireGuard Tunnel'
                DriverDescription = 'WireGuard Tunnel'
                DriverProvider = 'WireGuard LLC'
                DriverFileName = 'wireguard.sys'
            }
            $query = { @($adapter) }.GetNewClosure()
            New-WgstDefaultDnsRepairRequest `
                -AdapterQuery $query |
                ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var request = JsonSerializer.Deserialize<RepairRequest>(
            result.StandardOutput.Trim(),
            JsonOptions);
        request.Should().NotBeNull();
        request!.InterfaceGuid.Should().Be(guid.ToString("D"));
    }

    [Fact]
    public void DefaultRequest_RejectsEthernetAndRelabelledSg()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $adapters = @(
                [pscustomobject]@{
                    Name = 'Ethernet'
                    Status = 'Up'
                    InterfaceGuid = [guid]'{{Guid.NewGuid():D}}'
                    InterfaceIndex = 4
                    InterfaceDescription = 'Intel(R) Ethernet Controller'
                    DriverDescription = 'Intel(R) Ethernet Controller'
                    DriverProvider = 'Intel'
                    DriverFileName = 'e2f.sys'
                }
                [pscustomobject]@{
                    Name = 'SG'
                    Status = 'Up'
                    InterfaceGuid = [guid]'{{Guid.NewGuid():D}}'
                    InterfaceIndex = 5
                    InterfaceDescription = 'Intel(R) Ethernet Controller'
                    DriverDescription = 'Intel(R) Ethernet Controller'
                    DriverProvider = 'Intel'
                    DriverFileName = 'e2f.sys'
                }
            )
            $errors = @()
            foreach ($adapter in $adapters) {
                $current = $adapter
                $query = { @($current) }.GetNewClosure()
                try {
                    New-WgstDefaultDnsRepairRequest `
                        -AdapterQuery $query |
                        Out-Null
                }
                catch {
                    $errors += $_.Exception.Message
                }
            }
            $errors | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        var errors = JsonSerializer.Deserialize<string[]>(
            result.StandardOutput.Trim());
        errors.Should().HaveCount(2);
        errors.Should().OnlyContain(
            message => message.Contains(
                "verified active WireGuard/Wintun adapter",
                StringComparison.Ordinal));
    }

    [Fact]
    public void DefaultRequest_RejectsAmbiguousVerifiedActiveAdapters()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $adapters = @(
                {{VerifiedAdapter("first-tunnel", Guid.NewGuid())}}
                {{VerifiedAdapter("second-tunnel", Guid.NewGuid(), "wintun.sys")}}
            )
            $query = { @($adapters) }.GetNewClosure()
            New-WgstDefaultDnsRepairRequest `
                -AdapterQuery $query |
                Out-Null
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("ambiguous");
    }

    [Fact]
    public void RepairPayload_RoundTripsOnlyCanonicalGuid()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $payload = ConvertTo-WgstDnsRepairPayload `
                -InterfaceGuid '{{guid:D}}'
            ConvertFrom-WgstDnsRepairPayload `
                -Payload $payload |
                ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var document = JsonDocument.Parse(
            result.StandardOutput.Trim());
        document.RootElement.GetProperty("InterfaceGuid")
            .GetString().Should().Be(guid.ToString("D"));
        document.RootElement.TryGetProperty(
            "InterfaceIndex",
            out _).Should().BeFalse();
        document.RootElement.TryGetProperty(
            "DnsServers",
            out _).Should().BeFalse();
    }

    [Fact]
    public void RepairPayload_RejectsTrailingLf()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $payload = ConvertTo-WgstDnsRepairPayload `
                -InterfaceGuid '{{Guid.NewGuid():D}}'
            ConvertFrom-WgstDnsRepairPayload `
                -Payload ($payload + "`n") |
                Out-Null
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("DNS repair payload is invalid");
    }

    [Fact]
    public void CanonicalBase64Decoder_RejectsNonZeroPadBits()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            ConvertFrom-WgstCanonicalBase64 `
                -Payload 'Zh==' |
                Out-Null
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("noncanonical Base64");
    }

    [Fact]
    public void ElevatedLookup_RejectsGuidReplacementWithWrongProvenance()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $replacement = [pscustomobject]@{
                Name = 'SG'
                Status = 'Up'
                InterfaceGuid = [guid]'{{guid:D}}'
                InterfaceIndex = 23
                InterfaceDescription = 'Intel(R) Ethernet Controller'
                DriverDescription = 'Intel(R) Ethernet Controller'
                DriverProvider = 'Intel'
                DriverFileName = 'e2f.sys'
            }
            $query = { @($replacement) }.GetNewClosure()
            Resolve-WgstElevatedDnsRepairAdapter `
                -InterfaceGuid '{{guid:D}}' `
                -AdapterQuery $query
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("provenance");
    }

    [Fact]
    public void ElevatedLookup_DerivesCurrentAliasFromVerifiedGuid()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $renamed = {{VerifiedAdapter("renamed-after-uac", guid)}}
            $query = { @($renamed) }.GetNewClosure()
            Resolve-WgstElevatedDnsRepairAdapter `
                -InterfaceGuid '{{guid:D}}' `
                -AdapterQuery $query |
                Select-Object -ExpandProperty Name
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        result.StandardOutput.Trim().Should().Be("renamed-after-uac");
    }

    [Fact]
    public void ElevatedLookup_RejectsAmbiguousGuidMatches()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $matches = @(
                {{VerifiedAdapter("first-name", guid)}}
                {{VerifiedAdapter("second-name", guid)}}
            )
            $query = { @($matches) }.GetNewClosure()
            Resolve-WgstElevatedDnsRepairAdapter `
                -InterfaceGuid '{{guid:D}}' `
                -AdapterQuery $query
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("ambiguous");
    }

    [Fact]
    public void Mutation_UsesStableIndexOnceAndVerifiesExactPostState()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $authorized = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $snapshots = [Collections.Generic.Queue[object]]::new()
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $capture = [pscustomobject]@{
                SetterCalls = 0
                SetterIndex = 0
                SetterServers = @()
                ReaderCalls = 0
                FlusherCalls = 0
            }
            $query = { $snapshots.Dequeue() }.GetNewClosure()
            $setter = {
                param([int]$InterfaceIndex, [string[]]$Servers)
                $capture.SetterCalls++
                $capture.SetterIndex = $InterfaceIndex
                $capture.SetterServers = @($Servers)
            }.GetNewClosure()
            $reader = {
                param([int]$InterfaceIndex)
                $capture.ReaderCalls++
                [pscustomobject]@{
                    InterfaceIndex = $InterfaceIndex
                    ServerAddresses = @('8.8.8.8', '1.1.1.1')
                }
            }.GetNewClosure()
            $flusher = {
                $capture.FlusherCalls++
                0
            }.GetNewClosure()
            $target = Invoke-WgstApprovedDnsMutation `
                -AuthorizedAdapter $authorized `
                -AdapterQuery $query `
                -DnsSetter $setter `
                -DnsReader $reader `
                -CacheFlusher $flusher
            [pscustomobject]@{
                TargetName = $target.Name
                TargetIndex = $target.InterfaceIndex
                SetterCalls = $capture.SetterCalls
                SetterIndex = $capture.SetterIndex
                SetterServers = @($capture.SetterServers)
                ReaderCalls = $capture.ReaderCalls
                FlusherCalls = $capture.FlusherCalls
            } | ConvertTo-Json -Compress
            """);

        result.ExitCode.Should().Be(0, result.CombinedOutput);
        using var document = JsonDocument.Parse(
            result.StandardOutput.Trim());
        document.RootElement.GetProperty("TargetName")
            .GetString().Should().Be("SG");
        document.RootElement.GetProperty("TargetIndex")
            .GetInt32().Should().Be(41);
        document.RootElement.GetProperty("SetterCalls")
            .GetInt32().Should().Be(1);
        document.RootElement.GetProperty("SetterIndex")
            .GetInt32().Should().Be(41);
        document.RootElement.GetProperty("SetterServers")
            .EnumerateArray()
            .Select(item => item.GetString())
            .Should().Equal("8.8.8.8", "1.1.1.1");
        document.RootElement.GetProperty("ReaderCalls")
            .GetInt32().Should().Be(1);
        document.RootElement.GetProperty("FlusherCalls")
            .GetInt32().Should().Be(1);
    }

    [Fact]
    public void Mutation_PropagatesSetterFailure()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $authorized = {{VerifiedAdapter("SG", guid)}}
            $query = { {{VerifiedAdapter("SG", guid)}} }
            $setter = { throw 'setter_failed' }
            $never = { throw 'must_not_run' }
            Invoke-WgstApprovedDnsMutation `
                -AuthorizedAdapter $authorized `
                -AdapterQuery $query `
                -DnsSetter $setter `
                -DnsReader $never `
                -CacheFlusher $never
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("setter_failed");
        result.CombinedOutput.Should().NotContain("must_not_run");
    }

    [Theory]
    [InlineData("Before", "Rename")]
    [InlineData("Before", "Status")]
    [InlineData("Before", "Provenance")]
    [InlineData("Before", "Index")]
    [InlineData("After", "Rename")]
    [InlineData("After", "Status")]
    [InlineData("After", "Provenance")]
    [InlineData("After", "Index")]
    public void Mutation_RejectsAdapterChange(
        string phase,
        string change)
    {
        var guid = Guid.NewGuid();
        var changeSource = change switch
        {
            "Rename" => "$changed.Name = 'renamed'",
            "Status" => "$changed.Status = 'Down'",
            "Provenance" => "$changed.DriverProvider = 'Microsoft'",
            "Index" => "$changed.InterfaceIndex = 99",
            _ => throw new ArgumentOutOfRangeException(nameof(change))
        };
        var before = phase == "Before" ? "$changed" : "$sameBefore";
        var after = phase == "After" ? "$changed" : "$sameAfter";
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $authorized = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $sameBefore = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $sameAfter = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $changed = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            {{changeSource}}
            $snapshots = [Collections.Generic.Queue[object]]::new()
            $snapshots.Enqueue({{before}})
            $snapshots.Enqueue({{after}})
            $query = { $snapshots.Dequeue() }.GetNewClosure()
            $setter = { }
            $reader = {
                [pscustomobject]@{
                    ServerAddresses = @('8.8.8.8', '1.1.1.1')
                }
            }
            $flusher = { 0 }
            Invoke-WgstApprovedDnsMutation `
                -AuthorizedAdapter $authorized `
                -AdapterQuery $query `
                -DnsSetter $setter `
                -DnsReader $reader `
                -CacheFlusher $flusher
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("adapter changed");
    }

    [Theory]
    [InlineData("Partial")]
    [InlineData("Reordered")]
    [InlineData("Extra")]
    public void Mutation_RejectsMismatchedPostState(string shape)
    {
        var guid = Guid.NewGuid();
        var addresses = shape switch
        {
            "Partial" => "@('8.8.8.8')",
            "Reordered" => "@('1.1.1.1', '8.8.8.8')",
            "Extra" => "@('8.8.8.8', '1.1.1.1', '9.9.9.9')",
            _ => throw new ArgumentOutOfRangeException(nameof(shape))
        };
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $authorized = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $snapshots = [Collections.Generic.Queue[object]]::new()
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $query = { $snapshots.Dequeue() }.GetNewClosure()
            $setter = { }
            $reader = {
                [pscustomobject]@{
                    ServerAddresses = {{addresses}}
                }
            }
            $flusher = { throw 'flush_must_not_run' }
            Invoke-WgstApprovedDnsMutation `
                -AuthorizedAdapter $authorized `
                -AdapterQuery $query `
                -DnsSetter $setter `
                -DnsReader $reader `
                -CacheFlusher $flusher
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("post-verification");
        result.CombinedOutput.Should().NotContain("flush_must_not_run");
    }

    [Fact]
    public void Mutation_RejectsNonzeroCacheFlushExitCode()
    {
        var guid = Guid.NewGuid();
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            $authorized = {{VerifiedAdapter("SG", guid, interfaceIndex: 41)}}
            $snapshots = [Collections.Generic.Queue[object]]::new()
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $snapshots.Enqueue({{VerifiedAdapter("SG", guid, interfaceIndex: 41)}})
            $query = { $snapshots.Dequeue() }.GetNewClosure()
            $reader = {
                [pscustomobject]@{
                    ServerAddresses = @('8.8.8.8', '1.1.1.1')
                }
            }
            Invoke-WgstApprovedDnsMutation `
                -AuthorizedAdapter $authorized `
                -AdapterQuery $query `
                -DnsSetter { } `
                -DnsReader $reader `
                -CacheFlusher { 7 }
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain("exit code 7");
    }

    [Fact]
    public void MutationSource_UsesDnsClientAndChecksNativeFlushExit()
    {
        var source = File.ReadAllText(FixDnsScript);

        source.Should().Contain("DnsClient\\Set-DnsClientServerAddress");
        source.Should().Contain("DnsClient\\Get-DnsClientServerAddress");
        source.Should().Contain("$LASTEXITCODE");
        source.Should().NotContain("& $netshPath");
    }

    [Fact]
    public void RepairPayloadDecoder_BoundsEncodedPayload()
    {
        var result = RunInlinePowerShell($$"""
            $ErrorActionPreference = 'Stop'
            . '{{Escape(FixDnsScript)}}' -LibraryOnly
            ConvertFrom-WgstDnsRepairPayload `
                -Payload ('A' * 129) |
                Out-Null
            """);

        result.ExitCode.Should().NotBe(0);
        result.CombinedOutput.Should().Contain(
            "DNS repair payload is invalid");
    }

    [Fact]
    public void PublicEntrypoint_RejectsLegacyDnsArguments()
    {
        var result = ReleaseScriptFixture.RunPowerShell(
            FixDnsScript,
            "-LibraryOnly",
            "-DnsServers",
            "9.9.9.9");

        result.ExitCode.Should().NotBe(0);
        File.ReadAllText(FixDnsScript).Should().Contain(
            "[CmdletBinding(PositionalBinding = $false)]");
    }

    [Fact]
    public void UacBoundary_TransportsOnlyBoundedRepairPayloadNotAdapterAlias()
    {
        var source = File.ReadAllText(FixDnsScript);
        var main = source.IndexOf(
            "if ($LibraryOnly)",
            StringComparison.Ordinal);
        var parameterBlock = source[..source.IndexOf(
            "$ErrorActionPreference",
            StringComparison.Ordinal)];

        main.Should().BeGreaterThanOrEqualTo(0);
        parameterBlock.Should().NotContain("$AdapterName");
        parameterBlock.Should().NotContain("$DnsServers");
        source.Should().Contain("'-DnsRepairPayload'");
        source.Should().NotContain("'-AdapterName'");
        source.Should().NotContain("'-DnsServersPayload'");
        source.Should().NotContain("Resolve-WireGuardAdapterName");
    }

    public void Dispose()
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private string FixDnsScript =>
        Path.Combine(repositoryRoot, "scripts", "fix-dns.ps1");

    private ScriptProcessResult RunInlinePowerShell(
        string source,
        params string[] arguments)
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(
            root,
            $"inline-{Guid.NewGuid():N}.ps1");
        File.WriteAllText(
            path,
            source,
            new UTF8Encoding(false));
        return ReleaseScriptFixture.RunPowerShell(path, arguments);
    }

    private static string VerifiedAdapter(
        string name,
        Guid interfaceGuid,
        string driverFileName = "wireguard.sys",
        int interfaceIndex = 23) =>
        $$"""
        [pscustomobject]@{
            Name = '{{Escape(name)}}'
            Status = 'Up'
            InterfaceGuid = [guid]'{{interfaceGuid:D}}'
            InterfaceIndex = {{interfaceIndex}}
            InterfaceDescription = 'WireGuard Tunnel'
            DriverDescription = 'WireGuard Tunnel'
            DriverProvider = 'WireGuard LLC'
            DriverFileName = '{{Escape(driverFileName)}}'
        }
        """;

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

    private static readonly JsonSerializerOptions JsonOptions =
        new()
        {
            PropertyNameCaseInsensitive = true
        };

    private sealed record RepairRequest(string InterfaceGuid);
}
