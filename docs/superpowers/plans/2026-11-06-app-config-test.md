# Windows App Selected-Config Test Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Windows WPF `Test Config` action which tests the selected NordVPN config, applies only a verified same-country repair, restores networking, and offers the exact unrepaired source file for Recycle Bin deletion.

**Architecture:** Put parsing, metadata validation, byte-preserving patching, and workflow orchestration in Core behind a small adapter interface. Keep all live Windows operations behind that interface and all prompts/state changes in a focused WPF partial class. Offline tests use fake adapters and synthetic files; no test invokes a real tunnel, route, service, update, or Recycle Bin operation.

**Tech Stack:** .NET 8, C#, WPF, xUnit, FluentAssertions, WireGuard/wg.exe, Windows system curl.exe, existing `StateStore` and `FileAppLogger`.

**Execution constraints:** Preserve all unrelated uncommitted work. Do not commit, pull, push, run a live VPN check, change real routes/services, or recycle a real config unless the owner separately authorizes that exact action. The approved spec is `docs/superpowers/specs/2026-11-06-app-config-test-design.md`.

---

## File Map

- Create `src/WireguardSplitTunnel.Core/ConfigCheck/ConfigCheckModels.cs`: immutable config/server/probe/result models and adapter contracts.
- Create `src/WireguardSplitTunnel.Core/ConfigCheck/CheckedConfig.cs`: safe plaintext NordVPN parser and byte-preserving peer patcher.
- Create `src/WireguardSplitTunnel.Core/ConfigCheck/NordVpnMetadata.cs`: bounded JSON metadata validation.
- Create `src/WireguardSplitTunnel.Core/ConfigCheck/ConfigCheckWorkflow.cs`: candidate ordering, test/commit decisions, guaranteed restore.
- Create `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckPrimitives.cs`: pure native argument, handshake, path, and fingerprint helpers.
- Create `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckAdapter.cs`: live backup/session/service/probe/recovery/recycle implementation, excluded from offline execution.
- Create `src/WireguardSplitTunnel.App/MainWindow.ConfigCheck.cs`: selected-only UI coordination, confirmations, state/list updates, close exclusion.
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml`: add `Test Config` beside the selected-config controls.
- Modify `src/WireguardSplitTunnel.App/MainWindow.xaml.cs`: construct the UI coordinator, wire the button, and gate enable/renew/close work.
- Modify `README.md`: document the released-app action, interruption, repair, Recycle Bin, and recovery behavior.
- Create focused test files under `tests/WireguardSplitTunnel.Core.Tests/ConfigCheck*.cs` and one Windows app wiring contract test.

### Task 1: Config Models And Parser

**Files:**
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/ConfigCheckModels.cs`
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/CheckedConfig.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckParserTests.cs`

- [ ] **Step 1: Write parser rejection and round-trip tests**

```csharp
using System.Text;
using FluentAssertions;
using WireguardSplitTunnel.Core.ConfigCheck;

namespace WireguardSplitTunnel.Core.Tests;

public sealed class ConfigCheckParserTests : IDisposable
{
    private readonly string root = Directory.CreateTempSubdirectory("wgst-config-check-").FullName;
    private const string PrivateKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    private const string PublicKey = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==";
    private const string Valid = "[Interface]\r\nPrivateKey = {0}\r\nAddress = 10.5.0.2/32\r\nDNS = 103.86.96.100\r\n\r\n[Peer]\r\nPublicKey = {1} # keep\r\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\nEndpoint = uk6000.nordvpn.com:51820 # keep\r\n";

    [Fact]
    public void Parse_RetainsIdentityAndFingerprint()
    {
        var path = Write("GB.conf", string.Format(Valid, PrivateKey, PublicKey));
        var config = CheckedConfig.Parse(path);
        config.Path.Should().Be(Path.GetFullPath(path));
        config.HostName.Should().Be("uk6000.nordvpn.com");
        config.Country.Should().Be("GB");
        config.SourceAddress.Should().Be("10.5.0.2");
        config.Fingerprint.Should().HaveLength(64);
    }

    [Theory]
    [InlineData("PostUp = malicious-command", "hooks")]
    [InlineData("PresharedKey = " + PublicKey, "preshared keys")]
    [InlineData("[Peer]", "multiple peers")]
    public void Parse_RejectsUnsafeOrUnsupportedInput(string addition, string reason)
    {
        var path = Write("invalid.conf", string.Format(Valid, PrivateKey, PublicKey) + addition + "\r\n");
        Action parse = () => CheckedConfig.Parse(path);
        parse.Should().Throw<InvalidDataException>(reason);
    }

    [Fact]
    public void Parse_RejectsDpapiAndNonNordEndpoints()
    {
        File.WriteAllText(Path.Combine(root, "secret.conf.dpapi"), "secret");
        Action dpapi = () => CheckedConfig.Parse(Path.Combine(root, "secret.conf.dpapi"));
        dpapi.Should().Throw<InvalidDataException>();
        var path = Write("other.conf", string.Format(Valid, PrivateKey, PublicKey).Replace("uk6000.nordvpn.com", "vpn.example.org"));
        Action other = () => CheckedConfig.Parse(path);
        other.Should().Throw<InvalidDataException>();
    }

    private string Write(string name, string text)
    {
        var path = Path.Combine(root, name);
        File.WriteAllText(path, text, new UTF8Encoding(false));
        return path;
    }

    public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, true); }
}
```

- [ ] **Step 2: Run the tests and verify the expected compile failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckParserTests`
Expected: FAIL because `WireguardSplitTunnel.Core.ConfigCheck.CheckedConfig` does not exist.

- [ ] **Step 3: Add the immutable contracts**

```csharp
namespace WireguardSplitTunnel.Core.ConfigCheck;

public enum ConfigCheckStatus { Healthy, Repaired, Unrepaired }
public sealed record ConfigCheckServer(string HostName, string PublicKey, string Country);
public sealed record ConfigCheckProbe(bool Success, string Reason, string ObservedCountry);
public sealed record ConfigCheckResult(ConfigCheckStatus Status, string ConfigPath, string Endpoint, string Reason);

public interface IConfigCheckSession { string PrivateRoot { get; } }

public interface IConfigCheckAdapter
{
    Task<IReadOnlyList<ConfigCheckServer>> GetCandidatesAsync(string country, int limit, CancellationToken token);
    Task<IConfigCheckSession> BeginAsync(CheckedConfig config, CancellationToken token);
    Task StopOriginalAsync(IConfigCheckSession session, CancellationToken token);
    Task<ConfigCheckProbe> TestAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token);
    Task CommitAsync(IConfigCheckSession session, CheckedConfig config, ConfigCheckServer server, CancellationToken token);
    Task RestoreAsync(IConfigCheckSession session, CancellationToken token);
    Task RecycleUnrepairedAsync(CheckedConfig config, CancellationToken token);
}
```

- [ ] **Step 4: Implement the bounded parser and exact patcher**

Create `CheckedConfig` with this exact public surface:

```csharp
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public sealed record CheckedConfig(
    string Path, string Name, string Text, byte[] Bytes, Encoding Encoding, byte[] Preamble,
    string Fingerprint, string PrivateKey, string PublicKey, string HostName, int Port,
    string Country, string SourceAddress, string Endpoint)
{
    public static CheckedConfig Parse(string path) => ConfigCheckParser.Parse(path);
    public byte[] WithPeerServer(ConfigCheckServer server) => ConfigCheckParser.PatchPeer(this, server);
    public static string FingerprintBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
```

Implement internal static `ConfigCheckParser` with these concrete rules: canonical full path; `.conf` only; no reparse point in the file or parent directory; maximum 65,536 bytes; strict UTF-8/UTF-16 BOM decoding; one `[Interface]` and one `[Peer]`; unique allowed scalar fields only; 32-byte Base64 keys; IPv4 client Address; valid AllowedIPs prefixes; no hooks or preshared key; endpoint regex `^(?<host>[a-z]{2}[0-9]+\.nordvpn\.com):(?<port>[0-9]+)$`; port 1–65535; country is the first two hostname letters uppercased. `PatchPeer` must require the same country and a valid key, replace exactly one `Endpoint` and one `PublicKey` line with a regex evaluator which retains whitespace/comments, and prepend the original BOM. Throw `InvalidDataException` on every rejection without including config text or key material in the message.

- [ ] **Step 5: Run parser tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckParserTests`
Expected: PASS; no network or service access occurs.

### Task 2: Patch Preservation And Metadata Validation

**Files:**
- Modify: `src/WireguardSplitTunnel.Core/ConfigCheck/CheckedConfig.cs`
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/NordVpnMetadata.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckPatchTests.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/NordVpnMetadataTests.cs`

- [ ] **Step 1: Write failing byte-preservation tests**

```csharp
[Fact]
public void PatchPeer_ChangesOnlyEndpointAndPublicKey()
{
    var before = Encoding.UTF8.GetBytes(sourceTextWithCommentsAndCrlf);
    var config = CheckedConfig.Parse(Write("GB.conf", sourceTextWithCommentsAndCrlf));
    var server = new ConfigCheckServer("uk6001.nordvpn.com", replacementBase64Key, "GB");
    var patched = config.WithPeerServer(server);
    Encoding.UTF8.GetString(patched).Should().Be(expectedTextWithOnlyPeerValuesChanged);
    patched.Take(Encoding.UTF8.GetPreamble().Length).Should().Equal(Encoding.UTF8.GetPreamble());
}

[Fact]
public void PatchPeer_RejectsWrongCountryAndInvalidKey()
{
    Action wrongCountry = () => config.WithPeerServer(config.OriginalServer with { Country = "US" });
    Action invalidKey = () => config.WithPeerServer(config.OriginalServer with { PublicKey = "invalid" });
    wrongCountry.Should().Throw<InvalidDataException>();
    invalidKey.Should().Throw<InvalidDataException>();
}
```

Add `OriginalServer => new(HostName, PublicKey, Country)` to `CheckedConfig`. Include explicit UTF-8 BOM and UTF-16LE fixtures in the test class; compare all non-peer lines and preamble bytes exactly.

- [ ] **Step 2: Run patch tests and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckPatchTests`
Expected: FAIL because `OriginalServer` and complete BOM-preserving patch behavior are absent.

- [ ] **Step 3: Complete patch behavior and add metadata tests**

```csharp
[Theory]
[InlineData("uk6000.nordvpn.com.attacker.example")]
[InlineData("US1.nordvpn.com")]
[InlineData("uk6000.example.com")]
public void CountryFromHost_RejectsLookalikes(string host)
{
    Action parse = () => NordVpnMetadata.CountryFromHost(host);
    parse.Should().Throw<InvalidDataException>();
}

[Fact]
public void SelectCandidates_RequiresOneTrustedSameCountryRecord()
{
    var records = JsonDocument.Parse(metadataJsonWithOnlineOfflineDuplicateWrongCountryAndInvalidKeyRecords);
    var selected = NordVpnMetadata.SelectCandidates(records.RootElement, "GB", 3);
    selected.Should().ContainSingle();
    selected[0].HostName.Should().Be("uk6001.nordvpn.com");
}
```

- [ ] **Step 4: Run metadata tests and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~NordVpnMetadataTests`
Expected: FAIL because `NordVpnMetadata` is absent.

- [ ] **Step 5: Implement metadata validation**

```csharp
using System.Text.Json;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class NordVpnMetadata
{
    public static string CountryFromHost(string host) => CheckedConfig.ParseEndpoint(host + ":51820").Country;

    public static IReadOnlyList<ConfigCheckServer> SelectCandidates(JsonElement servers, string country, int limit)
    {
        if (servers.ValueKind != JsonValueKind.Array || limit is < 1 or > 5) throw new InvalidDataException("Invalid metadata.");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var selected = new List<ConfigCheckServer>();
        foreach (var server in servers.EnumerateArray())
        {
            if (selected.Count >= limit) break;
            if (server.GetProperty("status").GetString() != "online") continue;
            var host = server.GetProperty("hostname").GetString() ?? "";
            string serverCountry;
            try { serverCountry = CountryFromHost(host); } catch (InvalidDataException) { continue; }
            if (serverCountry != country || !seen.Add(host)) continue;
            if (!HasSingleCountry(server, country)) continue;
            var key = SingleOnlineWireGuardKey(server);
            if (key is null) continue;
            selected.Add(new ConfigCheckServer(host.ToLowerInvariant(), key, country));
        }
        return selected;
    }

    private static bool HasSingleCountry(JsonElement server, string country) =>
        server.GetProperty("locations").EnumerateArray().Select(location => location.GetProperty("country").GetProperty("code").GetString()).Distinct(StringComparer.Ordinal).SingleOrDefault() == country;

    private static string? SingleOnlineWireGuardKey(JsonElement server)
    {
        var technologies = server.GetProperty("technologies").EnumerateArray().Where(technology =>
            technology.GetProperty("identifier").GetString() == "wireguard_udp" &&
            technology.GetProperty("pivot").GetProperty("status").GetString() == "online").ToArray();
        if (technologies.Length != 1) return null;
        var keys = technologies[0].GetProperty("metadata").EnumerateArray().Where(item => item.GetProperty("name").GetString() == "public_key").Select(item => item.GetProperty("value").GetString()).ToArray();
        return keys.Length == 1 && CheckedConfig.IsValidKey(keys[0]) ? keys[0] : null;
    }
}
```

Expose internal `ParseEndpoint` and `IsValidKey` from `CheckedConfig`; wrap malformed individual metadata records so they are skipped, while malformed top-level JSON is fatal.

- [ ] **Step 6: Run parser, patch, and metadata tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~ConfigCheckParserTests|FullyQualifiedName~ConfigCheckPatchTests|FullyQualifiedName~NordVpnMetadataTests"`
Expected: PASS.

### Task 3: Restore-Safe Workflow

**Files:**
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/ConfigCheckWorkflow.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckWorkflowTests.cs`

- [ ] **Step 1: Write a recording fake adapter and failing workflow tests**

```csharp
[Fact]
public async Task FailedOriginal_CommitsOnlyFirstVerifiedSameCountryCandidate()
{
    var adapter = new FakeAdapter
    {
        Probe = (config, server) => Task.FromResult(new ConfigCheckProbe(server.HostName == "uk6001.nordvpn.com", "HandshakeFailed", "GB"))
    };
    adapter.Candidates.AddRange([new("uk6000.nordvpn.com", config.PublicKey, "GB"), new("uk6001.nordvpn.com", replacementKey, "GB"), new("uk6002.nordvpn.com", replacementKey2, "GB")]);
    var result = await ConfigCheckWorkflow.RunAsync(config, adapter.Object, CancellationToken.None);
    result.Status.Should().Be(ConfigCheckStatus.Repaired);
    adapter.Committed.Select(server => server.HostName).Should().Equal("uk6001.nordvpn.com");
    adapter.Events.Should().StartWith(["candidates", "begin", "stop"]).And.EndWith("restore");
}

[Fact]
public async Task HealthyAndFatalPaths_NeverCommit_AndAlwaysRestoreAfterBegin()
{
    var healthy = new FakeAdapter { Probe = (_, _) => Task.FromResult(new ConfigCheckProbe(true, "OK", "GB")) };
    (await ConfigCheckWorkflow.RunAsync(config, healthy.Object, CancellationToken.None)).Status.Should().Be(ConfigCheckStatus.Healthy);
    healthy.Committed.Should().BeEmpty();

    var fatal = new FakeAdapter { Probe = (_, _) => throw new IOException("synthetic") };
    await FluentActions.Awaiting(() => ConfigCheckWorkflow.RunAsync(config, fatal.Object, CancellationToken.None)).Should().ThrowAsync<IOException>();
    fatal.Committed.Should().BeEmpty();
    fatal.Events.Last().Should().Be("restore");
}
```

Also add separate tests proving all-failed probes return `Unrepaired`, a wrong-country probe never commits, no identical original candidate is retried, at most three candidates are requested, candidate download occurs before `BeginAsync`, and a restore exception is propagated.

- [ ] **Step 2: Run workflow tests and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckWorkflowTests`
Expected: FAIL because `ConfigCheckWorkflow` is absent.

- [ ] **Step 3: Implement the complete workflow**

```csharp
namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class ConfigCheckWorkflow
{
    public static async Task<ConfigCheckResult> RunAsync(CheckedConfig config, IConfigCheckAdapter adapter, CancellationToken token)
    {
        var original = config.OriginalServer;
        var candidates = await adapter.GetCandidatesAsync(config.Country, 3, token).ConfigureAwait(false);
        var session = await adapter.BeginAsync(config, token).ConfigureAwait(false);
        try
        {
            await adapter.StopOriginalAsync(session, token).ConfigureAwait(false);
            var probe = await adapter.TestAsync(session, config, original, token).ConfigureAwait(false);
            if (probe.Success && probe.ObservedCountry == config.Country)
                return new(ConfigCheckStatus.Healthy, config.Path, config.Endpoint, "HandshakeAndHttpsVerified");

            var reason = probe.Reason;
            foreach (var candidate in candidates.Take(3))
            {
                if (candidate.Country != config.Country || !CheckedConfig.IsValidKey(candidate.PublicKey)) continue;
                if (candidate.HostName.Equals(original.HostName, StringComparison.OrdinalIgnoreCase) && candidate.PublicKey == original.PublicKey) continue;
                probe = await adapter.TestAsync(session, config, candidate, token).ConfigureAwait(false);
                reason = probe.Reason;
                if (!probe.Success || probe.ObservedCountry != config.Country) continue;
                await adapter.CommitAsync(session, config, candidate, token).ConfigureAwait(false);
                return new(ConfigCheckStatus.Repaired, config.Path, candidate.HostName + ":" + config.Port, "ReplacementVerifiedAndSaved");
            }
            return new(ConfigCheckStatus.Unrepaired, config.Path, config.Endpoint, reason);
        }
        finally
        {
            // Cancellation must never skip network restoration.
            await adapter.RestoreAsync(session, CancellationToken.None).ConfigureAwait(false);
        }
    }
}
```

- [ ] **Step 4: Run workflow tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckWorkflowTests`
Expected: PASS, including restore on every failure path.

### Task 4: Pure Windows Probe Primitives

**Files:**
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckPrimitives.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/WindowsConfigCheckPrimitivesTests.cs`

- [ ] **Step 1: Write failing native contract tests**

```csharp
[Fact]
public void ProbeArguments_DisableUserCurlConfigAndBindSource()
{
    var args = WindowsConfigCheckPrimitives.BuildCurlArguments("1.1.1.1", "10.5.0.2");
    args.Should().Equal(["-q", "-4", "--interface", "10.5.0.2", "--resolve", "www.cloudflare.com:443:1.1.1.1", "--noproxy", "*", "--proto", "=https", "--connect-timeout", "8", "--max-time", "15", "--max-filesize", "16384", "--fail", "--silent", "--show-error", "https://www.cloudflare.com/cdn-cgi/trace"]);
}

[Theory]
[InlineData("abc\t0\n", "abc", 100, false)]
[InlineData("abc\t100\n", "abc", 100, false)]
[InlineData("abc\t101\n", "abc", 100, true)]
[InlineData("other\t200\n", "abc", 100, false)]
public void FreshHandshake_RequiresExpectedPeerAndNewTimestamp(string output, string key, long started, bool expected)
{
    WindowsConfigCheckPrimitives.HasFreshHandshake(output, key, started).Should().Be(expected);
}
```

Add tests for a minimal probe config (`Table = off`, no DNS, no `/0`, persistent keepalive), 12-hex-character owned tunnel names, full-path containment, reparse-point rejection, lowercase SHA-256 fingerprints, and no raw native output in safe errors.

- [ ] **Step 2: Run primitive tests and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~WindowsConfigCheckPrimitivesTests`
Expected: FAIL because the primitive type is absent.

- [ ] **Step 3: Implement the pure helpers**

```csharp
using System.Net;
using System.Security.Cryptography;

namespace WireguardSplitTunnel.Core.ConfigCheck;

public static class WindowsConfigCheckPrimitives
{
    public static IReadOnlyList<string> BuildCurlArguments(string probeIp, string sourceAddress) =>
        ["-q", "-4", "--interface", sourceAddress, "--resolve", "www.cloudflare.com:443:" + probeIp, "--noproxy", "*", "--proto", "=https", "--connect-timeout", "8", "--max-time", "15", "--max-filesize", "16384", "--fail", "--silent", "--show-error", "https://www.cloudflare.com/cdn-cgi/trace"];

    public static bool HasFreshHandshake(string output, string publicKey, long started) =>
        output.Split('\r', '\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(line => line.Split('\t'))
            .Any(columns => columns.Length == 2 && columns[0] == publicKey && long.TryParse(columns[1], out var stamp) && stamp > started);

    public static string NewOwnedTunnelName() => "WGSTCheck-" + Guid.NewGuid().ToString("N")[..12];
    public static string NewProbeConfig(CheckedConfig config, ConfigCheckServer server) =>
        "[Interface]\r\nPrivateKey = " + config.PrivateKey + "\r\nAddress = " + config.SourceAddress + "/32\r\nTable = off\r\n\r\n[Peer]\r\nPublicKey = " + server.PublicKey + "\r\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\r\nEndpoint = " + server.HostName + ":" + config.Port + "\r\nPersistentKeepalive = 3\r\n";
    public static string FingerprintFile(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();
}
```

- [ ] **Step 4: Run primitive tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~WindowsConfigCheckPrimitivesTests`
Expected: PASS.

### Task 5: Live Windows Adapter Behind One Boundary

**Files:**
- Create: `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckAdapter.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/WindowsConfigCheckAdapterContractTests.cs`

- [ ] **Step 1: Write adapter contract tests with an injected native executor**

```csharp
[Fact]
public async Task ProbeFailure_RemovesOwnedTunnelBeforeReturning()
{
    var native = new FakeConfigCheckNative { InstallExitCode = 0, HandshakeOutput = "peer\t0\n" };
    var adapter = new WindowsConfigCheckAdapter(native, appDataRoot);
    var probe = await adapter.TestAsync(session, config, candidate, CancellationToken.None);
    probe.Success.Should().BeFalse();
    native.Events.Should().EndWith("verify-inactive", "delete-temp", "journal-clear");
}

[Fact]
public async Task ConcurrentSourceChange_BlocksCommitAndRecycle()
{
    File.WriteAllText(config.Path, changedSyntheticBytes);
    await FluentActions.Awaiting(() => adapter.CommitAsync(session, config, verifiedCandidate, CancellationToken.None)).Should().ThrowAsync<IOException>();
    await FluentActions.Awaiting(() => adapter.RecycleUnrepairedAsync(config, CancellationToken.None)).Should().ThrowAsync<IOException>();
    native.RecycleCalls.Should().Be(0);
}
```

Define `IConfigCheckNative` in the adapter file with methods for HTTP JSON, DNS, process execution, service snapshot/stop/start/delete, route add/delete, ACL directory creation, journal read/write, atomic replacement, inactive-interface verification, and Recycle Bin. The fake records every call and never accesses Windows.

- [ ] **Step 2: Run adapter contract tests and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~WindowsConfigCheckAdapterContractTests`
Expected: FAIL because the adapter/native boundary is absent.

- [ ] **Step 3: Implement adapter ordering and source guards**

Implement the interface exactly as Task 1. `GetCandidatesAsync` must fetch countries and recommendations before `BeginAsync`; `BeginAsync` must create the restricted private session directory, copy original bytes, and persist version-1 journal before `StopOriginalAsync`; `CommitAsync` must re-read and compare the source fingerprint before staged same-volume replacement and readback; `TestAsync` must journal the owned test identity before install and remove it in `finally`; `RestoreAsync` must remove owned test artifacts, recover an incomplete replacement, restart only recorded stopped services, and mark the journal complete only after verification; `RecycleUnrepairedAsync` must repeat the full-path/reparse/fingerprint checks and call the injected recycle operation exactly once.

Use these live commands through argument lists, never a concatenated shell command:

```text
wireguard.exe /installtunnelservice <owned-temp-config>
wireguard.exe /uninstalltunnelservice <owned-temp-name>
wg.exe show <owned-temp-name> latest-handshakes
curl.exe <BuildCurlArguments output>
sc.exe stop <recorded-service>
sc.exe start <recorded-service>
```

Use `Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(path, UIOption.OnlyErrorDialogs, RecycleOption.SendToRecycleBin)` only inside the production native recycle adapter. Do not include exception/config text in logs; return status codes and owned paths only.

- [ ] **Step 4: Add journal/recovery tests**

Test interrupted replacement recovery, changed service identity refusal, different-running-tunnel refusal, unknown newer source retention, failed owned-tunnel cleanup blocking original restart, completed journal blocking duplicate cleanup, and incomplete journal blocking the next check. Use only fake native state and temporary synthetic files.

- [ ] **Step 5: Run adapter tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~WindowsConfigCheckAdapterContractTests`
Expected: PASS with zero real Windows service, route, network, or recycle calls.

### Task 6: WPF Result And Deletion Coordination

**Files:**
- Create: `src/WireguardSplitTunnel.App/MainWindow.ConfigCheck.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckUiContractTests.cs`

- [ ] **Step 1: Write the failing deletion-policy test**

```csharp
[Theory]
[InlineData(ConfigCheckStatus.Healthy, false)]
[InlineData(ConfigCheckStatus.Repaired, false)]
[InlineData(ConfigCheckStatus.Unrepaired, true)]
public void OnlyUnrepairedMayOfferRecycle(ConfigCheckStatus status, bool expected)
{
    ConfigCheckDeletePolicy.MayOffer(status).Should().Be(expected);
}
```

- [ ] **Step 2: Run the policy test and verify failure**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckUiContractTests`
Expected: FAIL because `ConfigCheckDeletePolicy` is absent.

- [ ] **Step 3: Add the minimal policy and WPF coordinator**

```csharp
namespace WireguardSplitTunnel.Core.ConfigCheck;
public static class ConfigCheckDeletePolicy
{
    public static bool MayOffer(ConfigCheckStatus status) => status == ConfigCheckStatus.Unrepaired;
}
```

In `MainWindow.ConfigCheck.cs`, add an async `OnTestConfigClicked` which captures the original selected full path, parses it, shows the initial warning, disables `TunnelConfigCombo`, `RefreshConfigsButton`, `BrowseConfigButton`, `EnableTunnelButton`, and `TestConfigButton`, awaits `ConfigCheckWorkflow.RunAsync`, and restores controls in `finally`. On Unrepaired only, show:

```csharp
var answer = MessageBox.Show(
    this,
    $"Connection could not be repaired:\n{result.ConfigPath}\n\nMove this file to the Recycle Bin?",
    "Wireguard Split Tunnel",
    MessageBoxButton.YesNo,
    MessageBoxImage.Warning,
    MessageBoxResult.No);
if (answer == MessageBoxResult.Yes)
{
    await adapter.RecycleUnrepairedAsync(config, routingWorkCts.Token);
    state = state with { SelectedTunnelConfigPath = null };
    stateStore.Save(state);
    RefreshTunnelConfigOptions();
}
```

Log only status, path, endpoint, and reason. A changed file, recycle error, or fatal workflow error leaves selection/file intact and shows a safe error. Do not show deletion after cancellation, parse failure, metadata failure, backup failure, or restore failure.

- [ ] **Step 4: Run the deletion-policy test**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckUiContractTests`
Expected: PASS.

### Task 7: XAML, Mutual Exclusion, And Close Safety

**Files:**
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml:46-130`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.xaml.cs:47-64,72-195,211-260,999-1116`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.ConfigCheck.cs`
- Test: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckUiContractTests.cs`

- [ ] **Step 1: Add failing WPF wiring contract tests**

Read `MainWindow.ConfigCheck.cs` and `MainWindow.xaml` as text in `ConfigCheckUiContractTests`. Assert the exact `TestConfigButton` name/click wiring, selected-path use, initial `MessageBoxButton.YesNo` + `MessageBoxResult.No` interruption warning, unrepaired-only second confirmation, full path included, default-No recycle prompt, `configCheckInProgress` exclusion in enable/renew/close paths, and no recycle call for Healthy/Repaired/fatal/cancel.

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter FullyQualifiedName~ConfigCheckUiContractTests`
Expected: FAIL because the XAML and wiring are absent.

- [ ] **Step 2: Add the button without changing unrelated layout**

Add a sixth `Auto` column and place this control before Enable Now:

```xaml
<Button Grid.Column="4"
        x:Name="TestConfigButton"
        Content="Test Config"
        MinWidth="110"
        Margin="0,0,8,0"
        Padding="10,6"
        VerticalAlignment="Top" />
```

Move the existing Enable/Save/Load panel to `Grid.Column="5"`; do not change unrelated tabs or styles.

- [ ] **Step 3: Wire construction and one-flight exclusion**

In the constructor add `TestConfigButton.Click += OnTestConfigClicked;`. Add `private int configCheckInProgress;` and guard the entry point with `Interlocked.CompareExchange(ref configCheckInProgress, 1, 0) != 0`. Reset it in `finally`. Make `TryEnableSelectedTunnel`, automatic re-enable, and route renewal return/defer while this flag is nonzero. While a check is active, `OnWindowClosing` must set a deferred-close flag and keep `e.Cancel = true`; after `RestoreAsync` and UI cleanup complete, resume the existing close orchestrator rather than introducing a second route-restoration path.

- [ ] **Step 4: Run UI and existing wiring tests**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~ConfigCheckUiContractTests|FullyQualifiedName~WindowsUpdateWiringContractTests|FullyQualifiedName~WindowsBypassExitWiringTests"`
Expected: PASS; Enable Now, update, and exit wiring remain intact.

- [ ] **Step 5: Build the Windows app**

Run: `dotnet build WireguardSplitTunnel.sln --no-restore`
Expected: PASS with zero errors. Do not launch the app or start a tunnel.

### Task 8: Documentation And Full Offline Verification

**Files:**
- Modify: `README.md`
- Review: all Task 1–7 files

- [ ] **Step 1: Document the actual app behavior**

Add a Windows `Test selected config` section which states: selected plaintext single-peer NordVPN `.conf` only; warning/interruption; original then at most three same-country candidates; fresh handshake + bound HTTPS + matching country; verified Endpoint/PublicKey-only repair; original service/routing restoration; Unrepaired-only full-path Recycle Bin prompt defaulting to No; concurrent edits preserved; backup/recovery location; and offline tests do not prove live connectivity.

- [ ] **Step 2: Run every new focused test**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~ConfigCheck|FullyQualifiedName~NordVpnMetadata|FullyQualifiedName~WindowsConfigCheck"`
Expected: PASS for all new tests.

- [ ] **Step 3: Run the existing Core regression suite**

Run: `dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj`
Expected: PASS. If only Mac tests are skipped by existing platform conditions, report that fact exactly.

- [ ] **Step 4: Run the full solution verification**

Run: `dotnet test WireguardSplitTunnel.sln --no-restore`
Expected: PASS with zero failed tests. No test should produce a UAC prompt, temporary WireGuard service, route change, external HTTPS request, or Recycle Bin entry.

- [ ] **Step 5: Check formatting and scope**

Run: `git diff --check`
Expected: no output. Then inspect `git status --short` and `git diff --stat`; confirm all pre-existing uncommitted standalone-checker files remain present and no unrelated file was rewritten.

- [ ] **Step 6: Report verified and unverified behavior separately**

Report exact test/build counts and paths changed. State explicitly that real handshake/HTTPS repair, service restoration, Recycle Bin behavior, automatic update, and app-close networking remain unverified until their separately authorized live tests/investigations. Do not claim the two follow-up bugs were fixed by this feature.
