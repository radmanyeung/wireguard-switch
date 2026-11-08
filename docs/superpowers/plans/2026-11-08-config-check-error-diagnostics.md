# Test Config 例外診斷 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 保留 Test Config `WorkflowFailed` 的完整例外，讓實機重現能提供可定位的根因證據。

**Architecture:** 沿用現有 `IAppLogger.Error(string, Exception?)`，只在 `MainWindow.ConfigCheck.cs` 的 workflow catch 加入診斷輸出，不改 Core workflow、UI 或修復行為。以現有原始碼合約測試做紅綠驗證，再用隔離設定副本實機重現。

**Tech Stack:** C#、.NET 8、WPF、xUnit、FluentAssertions、PowerShell UI Automation。

---

### Task 1: 以合約測試鎖定例外紀錄

**Files:**
- Modify: `tests/WireguardSplitTunnel.Core.Tests/ConfigCheckUiContractTests.cs`
- Modify: `src/WireguardSplitTunnel.App/MainWindow.ConfigCheck.cs:94-99`

- [ ] **Step 1: 寫失敗測試**

在 `ConfigCheckUiContractTests` 加入：

```csharp
[Fact]
public void WorkflowFailure_LogsFullExceptionForDiagnosis()
{
    var source = ReadCoordinatorSource();
    var workflowCatch = ExtractBetween(
        source,
        "catch (Exception)",
        "async Task RestoreRoutesAsync");

    workflowCatch.Should().Contain(
        "logger.Error(\"Config check workflow failed.\", ex);");
}
```

將 catch 改為具名 `catch (Exception ex)` 後，測試應只檢查實際例外有傳入現有 logger，不要求記錄設定內容或指令參數。

- [ ] **Step 2: 跑單一測試，確認紅燈**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~ConfigCheckUiContractTests.WorkflowFailure_LogsFullExceptionForDiagnosis"
```

Expected: 1 項失敗，因為 `WorkflowFailed` catch 尚未包含 `logger.Error(..., ex)`。

- [ ] **Step 3: 加最小實作**

將 `RunWorkflowAsync` 的 catch 改為：

```csharp
catch (Exception ex)
{
    logger.Error("Config check workflow failed.", ex);
    LogConfigCheck("Fatal", config!.Path, config.Endpoint, "WorkflowFailed");
    ShowConfigCheckError(
        "Config test failed. No Recycle Bin action was taken. Review the selected config and network state before retrying.");
}
```

保留現有 `LogConfigCheck` 和使用者訊息，不加入 `.conf` 內容、PrivateKey 或原生指令參數。

- [ ] **Step 4: 跑相關測試及 build**

Run:

```bash
dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~ConfigCheckUiContractTests"
dotnet build src/WireguardSplitTunnel.App/WireguardSplitTunnel.App.csproj --no-restore
```

Expected: 合約測試全過；build 0 errors。

- [ ] **Step 5: 保留工作區改動，不 commit**

Run:

```bash
git diff -- src/WireguardSplitTunnel.App/MainWindow.ConfigCheck.cs tests/WireguardSplitTunnel.Core.Tests/ConfigCheckUiContractTests.cs
```

Expected: 只見上述診斷與測試改動；按用戶限制，不執行 commit、pull 或 push。

### Task 2: 實機重現並收集根因

**Files:**
- Use: `live-validation/GB-tested.conf`（含密鑰，不讀取或輸出內容）
- Modify: `live-validation/run-live-test-combo.ps1` 的測試副本路徑及輸出檔名
- Read: `src/WireguardSplitTunnel.App/bin/Debug/net8.0-windows/runtime.log` 的新例外區段
- Output: `live-validation/` 的新測試結果與網絡快照

- [ ] **Step 1: 準備隔離副本與測試腳本**

將 `GB-tested.conf` 複製為原掃描資料夾內的 `GB-test.conf`，不覆蓋任何現有檔案；以正式 parser probe 驗證，預期只輸出：

```text
PARSE_OK Host=uk6000.nordvpn.com Port=51820 Country=GB
```

更新 UI Automation 腳本使用相同隔離副本，並使用新輸出檔名，避免混合先前結果。腳本必須精確核對完整路徑、回收筒選 No、清理失敗選 Cancel，並在結束時還原 CH 和 AutoUpdate On。

- [ ] **Step 2: 啟動新 build 並重現一次**

啟動 App 時不提供隔離 `LOCALAPPDATA` 覆寫；確認 App 以提權身份運行。暫停自動更新後，只按 `TestConfigButton`，確認警告包含 `D:\wireguard switch\conf\GB-test.conf` 才按 Yes。最長等待 600 秒，再正常關閉，最長等待 150 秒。

Expected: 記錄實際 Healthy／Repaired／Unrepaired／Error，不預設測試成功；若清理失敗，保留 App 並停止強行關閉。

- [ ] **Step 3: 讀取新例外並定位邊界**

從 `Config check workflow failed.` 開始讀取完整例外及 stack trace，對照 `ConfigCheckWorkflow`、`WindowsConfigCheckAdapter` 或 `WindowsConfigCheckNative` 的實際行號。只複製非敏感 journal；不讀取 `original.bin`、臨時 `.conf` 或任何私密金鑰。

Expected: 例外指出失敗的原生呼叫或還原邊界；若仍無詳情，先核對實際运行的 build 和 runtime log 路徑，不猜測根因。

- [ ] **Step 4: 核對還原及移走密鑰副本**

確認原 CH／GB hash 不變、原選擇 CH、AutoUpdate On、測試副本 hash 不變。正常關閉後確認 App、WireGuard 进程及所有 `WireGuardTunnel$*` 服務為 0，並比較路由、DNS、網卡；HTTPS 的既有信任錯誤獨立報告。最後將 `GB-test.conf` 移回 `live-validation`，目的地存在時不得覆蓋。

Expected: 原掃描資料夾不再含測試副本；正常網絡只剩非 WireGuard 路由、DNS 與網卡。根因證據和實際未通過項目如實報告，不 commit 或 push。
