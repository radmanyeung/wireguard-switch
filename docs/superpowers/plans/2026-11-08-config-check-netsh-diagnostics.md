# Config Check `netsh` 安全診斷 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 保留有界且不洩密的 `netsh` 原生錯誤摘要，透過實機重現取得暫時 probe route 新增失敗的低層原因。

**Architecture:** 在 `WindowsConfigCheckPrimitives` 增加 `netsh` 專用摘要器，並只從 `WindowsConfigCheckNative.RunRequired` 的 `netsh.exe` 失敗分支呼叫。其他原生指令繼續使用不保留輸出的通用錯誤；先完成診斷及實機證據，再為具體路由修復建立精確的紅綠改動。

**Tech Stack:** C#、.NET 8、WPF、xUnit、FluentAssertions、PowerShell UI Automation。

**版本控制限制：** 按用戶要求，本計劃所有改動保持未 commit、未 pull、未 push。

---

### Task 1: `netsh` 安全摘要器

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/WindowsConfigCheckPrimitivesTests.cs:123-135`
- Modify: `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckPrimitives.cs:1-56`

- [ ] **Step 1: 寫安全摘要失敗測試**

在 `SafeNativeError_NeverIncludesRawNativeOutputOrKeyMaterial` 後加入：

```csharp
[Fact]
public void NetshError_PreservesLocalizedDiagnosticAndRedactsSecrets()
{
    var rawOutput = "路由新增失敗：\r\n元素找不到。\r\nPrivateKey = " + PrivateKey + "\r\n" + PublicKey;

    var error = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, rawOutput);

    error.Should().StartWith(
        "netsh.exe failed (exit code 1). Diagnostic: 路由新增失敗： 元素找不到。 [redacted] [redacted]");
    error.Should().NotContain("PrivateKey")
        .And.NotContain("PublicKey")
        .And.NotContain(PrivateKey)
        .And.NotContain(PublicKey)
        .And.NotContain("\r")
        .And.NotContain("\n");
}

[Fact]
public void NetshError_TruncatesLongOutputAndOmitsEmptyDiagnostic()
{
    var error = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, new string('x', 600));
    var empty = WindowsConfigCheckPrimitives.CreateSafeNetshError(1, " \r\n\t");

    error.Should().StartWith("netsh.exe failed (exit code 1). Diagnostic: " + new string('x', 512));
    error.Should().EndWith("… [truncated]");
    error.Length.Should().BeLessThan(570);
    empty.Should().Be("netsh.exe failed (exit code 1).");
}
```

保留現有通用 `CreateSafeNativeError` 測試不變，確保非 `netsh` 指令仍不輸出原生內容。

- [ ] **Step 2: 跑新測試確認紅燈**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~WindowsConfigCheckPrimitivesTests.NetshError_"
```

Expected: 測試專案 build 失敗並出現 CS0117，因為 `CreateSafeNetshError` 尚未定義；這是預期的編譯期紅燈，不是環境或測試語法錯誤。

- [ ] **Step 3: 實作有界過濾摘要**

在 `WindowsConfigCheckPrimitives.cs` 加入：

```csharp
using System.Text.RegularExpressions;
```

在類別內加入固定逾時的 Regex 及摘要方法：

```csharp
private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
private static readonly Regex SensitiveAssignment = new(
    @"(?i)\b(?:PrivateKey|PublicKey)\s*=\s*[^\r\n]*",
    RegexOptions.Compiled | RegexOptions.CultureInvariant,
    RegexTimeout);
private static readonly Regex WireGuardKey = new(
    @"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])",
    RegexOptions.Compiled | RegexOptions.CultureInvariant,
    RegexTimeout);
private static readonly Regex RepeatedWhitespace = new(
    @"\s+",
    RegexOptions.Compiled | RegexOptions.CultureInvariant,
    RegexTimeout);

public static string CreateSafeNetshError(int exitCode, string rawOutput)
{
    const int maxDiagnosticLength = 512;
    var generic = CreateSafeNativeError("netsh.exe", exitCode, string.Empty);
    var sanitized = SensitiveAssignment.Replace(rawOutput, "[redacted]");
    sanitized = WireGuardKey.Replace(sanitized, "[redacted]");
    sanitized = RepeatedWhitespace.Replace(sanitized, " ").Trim();
    if (sanitized.Length == 0) return generic;
    if (sanitized.Length > maxDiagnosticLength)
        sanitized = sanitized[..maxDiagnosticLength] + "… [truncated]";
    return generic + " Diagnostic: " + sanitized;
}
```

不要改變現有 `CreateSafeNativeError`。

- [ ] **Step 4: 跑摘要器及通用保密測試**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~WindowsConfigCheckPrimitivesTests"
```

Expected: 全部通過，包括新增 2 項及原有 `SafeNativeError_NeverIncludesRawNativeOutputOrKeyMaterial`。

### Task 2: 只將 `netsh` 失敗分支接到安全摘要

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/WindowsConfigCheckAdapterContractTests.cs`
- Modify: `src/WireguardSplitTunnel.Core/ConfigCheck/WindowsConfigCheckNative.cs:1148-1153`

- [ ] **Step 1: 寫原生接線失敗測試**

在 `WindowsConfigCheckAdapterContractTests` 加入：

```csharp
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
```

- [ ] **Step 2: 跑接線測試確認紅燈**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~WindowsConfigCheckAdapterContractTests.NetshFailure_UsesSanitizedDiagnosticWithoutLoggingRouteArguments"
```

Expected: 1 項失敗，因為實際 `IOException.Message` 仍只有通用 `netsh.exe failed (exit code 1).`。

- [ ] **Step 3: 只修改失敗分支**

將 `RunRequired` 改為：

```csharp
private async Task<ConfigCheckNativeResult> RunRequired(string fileName, IReadOnlyList<string> arguments, CancellationToken token)
{
    var result = await RunAsync(fileName, arguments, token).ConfigureAwait(false);
    if (result.ExitCode != 0)
    {
        var error = string.Equals(fileName, "netsh.exe", StringComparison.OrdinalIgnoreCase)
            ? WindowsConfigCheckPrimitives.CreateSafeNetshError(result.ExitCode, result.Output)
            : WindowsConfigCheckPrimitives.CreateSafeNativeError(fileName, result.ExitCode, result.Output);
        throw new IOException(error);
    }
    return result;
}
```

不要加入指令參數或修改 `RunAsync` 的輸出收集方式。

- [ ] **Step 4: 跑相關測試及 App build**

Run:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" test "tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj" --filter "FullyQualifiedName~WindowsConfigCheckPrimitivesTests|FullyQualifiedName~WindowsConfigCheckAdapterContractTests.NetshFailure_UsesSanitizedDiagnosticWithoutLoggingRouteArguments|FullyQualifiedName~ConfigCheckUiContractTests"
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" build "src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj" --no-restore
```

Expected: 測試 0 失敗；App build 0 errors。保留改動，不 commit。

### Task 3: 實機取得低層錯誤並安全清理

**Files:**
- Use: `live-validation/GB-diagnostic-tested.conf`（含密鑰，不讀取或輸出內容）
- Modify: `live-validation/run-live-test-combo.ps1` 的輸出名稱及 snapshot labels
- Read: `src/WireguardSplitTunnel.App/bin/Debug/net8.0-windows/runtime.log` 最新例外
- Output: `live-validation/netsh-diagnostic-*`

- [ ] **Step 1: 準備新證據名稱及隔離副本**

將腳本內兩個 `diagnostic-driver` 改為 `netsh-diagnostic-driver`，並將：

```powershell
Write-Snapshot 'diagnostic-after-config'
Write-Snapshot 'diagnostic-after-close'
```

改為：

```powershell
Write-Snapshot 'netsh-diagnostic-after-config'
Write-Snapshot 'netsh-diagnostic-after-close'
```

確認新輸出檔不存在，拒絕覆蓋舊證據。確認 App、`wireguard` 进程及 `WireGuardTunnel$*` 服務均為 0 後，將 `GB-diagnostic-tested.conf` 複製為 `D:\wireguard switch\conf\GB-test.conf`，不得覆蓋。

Run parser probe:

```bash
env "ProgramFiles=C:\Program Files" "ProgramFiles(x86)=C:\Program Files (x86)" "/c/Program Files/dotnet/dotnet.exe" run --project "D:\wireguard switch\.worktrees\app-config-test\live-validation\parse-probe\parse-probe.csproj" -- "D:\wireguard switch\conf\GB-test.conf"
```

Expected: 只輸出 `PARSE_OK Host=uk6000.nordvpn.com Port=51820 Country=GB`。

- [ ] **Step 2: 記錄測試前狀態**

Run:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\wireguard switch\.worktrees\app-config-test\live-validation\capture-state.ps1" -Label "netsh-diagnostic-before" -OutputDirectory "D:\wireguard switch\.worktrees\app-config-test\live-validation"
```

Expected: 寫入新 snapshot；既有 TLS trust error 可記錄但不能當作本次新故障。

- [ ] **Step 3: 啟動新 build 並重現一次**

提示用戶在 App 及測試工具的 UAC 按「是」，然後執行：

```powershell
$binary = "D:\wireguard switch\.worktrees\app-config-test\src\WireguardSplitTunnel.App\bin\Debug\net8.0-windows\WireguardSplitTunnel.App.exe"
$process = Start-Process -FilePath $binary -WorkingDirectory (Split-Path $binary) -Verb RunAs -PassThru
$root = "D:\wireguard switch\.worktrees\app-config-test\live-validation"
$arguments = @(
    "-NoProfile", "-ExecutionPolicy", "Bypass",
    "-File", "`"$root\run-live-test-combo.ps1`"",
    "-ProcessId", $process.Id.ToString(),
    "-LiveRoot", "`"$root`"")
$driver = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arguments -PassThru -Wait
$driver.ExitCode
```

腳本必須暫停 AutoUpdate、精確核對 `D:\wireguard switch\conf\GB-test.conf` 才按 Yes、只按 Test Config、回收筒選 No、還原 CH 和 AutoUpdate On；清理失敗只准 Cancel，不准 Close anyway。測試最長 600 秒，close 最長 150 秒。

Expected: 記錄實際結果，不預設成功。若 UAC 或權限被拒，停止並確認原 CH／AutoUpdate 狀態，不以非提權工具重試介面操作。

- [ ] **Step 4: 讀取新例外及判定修復閘口**

搜尋最新：

```text
Config check workflow failed.
```

讀取完整 `IOException`、`Diagnostic:` 及 stack trace。只接受能直接指出具體路由參數、網卡識別或路由狀態問題的證據作為最小修復依據；不根據常見原因猜測。

如果證據支持最小修復，在修改產品路由程式前，先把具體修復寫成新的紅燈測試及精確改動，並核對它不改變 workflow、journal 或清理所有權邊界。若需要重試、fallback、全域網絡改動或超出 probe route 建立／刪除範圍，停止並重新提交設計。

- [ ] **Step 5: 核對還原並移走密鑰副本**

從新 result JSON 核對原 CH／GB／測試副本 hash 不變、CH 選擇及 AutoUpdate On 已還原、App 正常退出、沒有 close error。確認 App、`wireguard` 进程及服務為 0。

用現有比對程式模式比較 `netsh-diagnostic-before` 與 `netsh-diagnostic-after-close`，輸出新的 `netsh-diagnostic-network-comparison.json`；路由、DNS、網卡必須沒有未解釋差異或 WireGuard 殘留。

確認測試已停止且 CH／AutoUpdate 已還原後，將 `D:\wireguard switch\conf\GB-test.conf` 移到：

```text
D:\wireguard switch\.worktrees\app-config-test\live-validation\GB-netsh-diagnostic-tested.conf
```

目的地存在時不得覆蓋。最終回報低層錯誤、Test Config 實際結果、設定還原、網絡清理及仍未測項目；如只完成診斷，明確寫「已定位，尚未修復」。
