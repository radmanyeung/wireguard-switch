# Config Check `netsh` 安全診斷及最小修復設計

**日期：** 2026-11-08

**狀態：** 已獲用戶批准設計方向，等待書面規格覆核

## 背景

實機 `Test Config` 已在 WireGuard 新握手成功後失敗。完整 stack trace 顯示 `WindowsConfigCheckAdapter.TestAsync` 呼叫 `AddProbeRouteAsync`，而 `netsh.exe` 以 exit code 1 結束。現有 `CreateSafeNativeError` 刻意不保留任何原生輸出，因此只知道失敗呼叫，無法確定 Windows 拒絕新增路由的低層原因。

## 目標

1. 在不洩漏密鑰、設定內容或完整原生指令參數的前提下，取得可診斷的 `netsh` 錯誤摘要。
2. 根據新證據決定是否有一個可直接支持的最小修復。
3. 以相同隔離副本重測，並證明原設定、選擇、AutoUpdate 及正常網絡均獲還原。

## 非目標

- 不盲目重試或同時改用多套路由工具。
- 不重新設計 Config Check workflow、修復候選邏輯、回收筒流程或關閉流程。
- 不記錄 `.conf` 內容、PrivateKey、PublicKey、完整指令參數或其他原生指令的原始輸出。
- 不執行真實自動更新、commit、pull 或 push。
- 不在證據不足時宣稱已修復。

## 方案比較

### 方案 A：只對 `netsh` 提供有界、過濾後的錯誤摘要（採用）

能取得實際 Windows 錯誤，同時維持其他原生指令的保密邊界。這是最小且可測試的診斷改動。

### 方案 B：只回報預設錯誤分類

依賴不同語系的錯誤文字對照；新錯誤或本地化差異仍會令診斷中斷，因此不採用。

### 方案 C：直接更換路由指令或加入重試

目前沒有證據支持具體替代指令，可能掩蓋故障或產生額外路由，因此不採用。

## 設計

### 1. `netsh` 專用安全錯誤摘要

保留現有通用 `CreateSafeNativeError` 對所有原生指令的預設保密行為。另設 `netsh` 專用摘要路徑，只由 `RunRequired("netsh.exe", ...)` 的失敗分支使用。

摘要規則：

- 包含 `netsh.exe`、exit code 及有界錯誤摘要。
- 原始錯誤輸出最多保留 512 個 Unicode 字元；超出時明確標記已截斷。
- 在截斷前先移除或取代 `PrivateKey = ...`、`PublicKey = ...` 等敏感指派內容，並過濾符合 WireGuard base64 密鑰格式的獨立字串。
- 正規化換行及多餘空白，避免日誌偽造額外條目。
- 空白或過濾後無可顯示內容時，只回報現有通用錯誤。
- 不加入完整指令參數、設定路徑內容或 `.conf` 文字。

單元測試必須注入中英文示例、敏感指派、獨立密鑰格式字串、超長輸出、空白輸出及含換行輸出，證明診斷有用且敏感資料不會穿過摘要器。現有 `SafeNativeError_NeverIncludesRawNativeOutputOrKeyMaterial` 必須保持通過，防止其他原生指令被一併放寬。

### 2. 實機重現閘口

先只加入上述診斷並建置 App，再以 `GB-diagnostic-tested.conf` 建立新的 `D:\wireguard switch\conf\GB-test.conf`，不得覆蓋已有檔案。正式 parser probe 必須先通過。

UI Automation 必須：

- 以管理員身份操作同樣提權的 App。
- 暫停 AutoUpdate，避免真實更新。
- 精確核對警告內的完整測試副本路徑後才按 Yes。
- 只按 `TestConfigButton`；回收筒提示一律 No。
- 測試後還原 CH 和 AutoUpdate On。
- 正常關閉失敗時只 Cancel；不得 Close anyway 或強行關閉。

讀取最新 `Config check workflow failed.` 的完整例外及 `netsh` 摘要。只有錯誤直接指出具體參數、網卡識別或路由狀態問題，才進入最小修復；否則停止於診斷結果並明確報告尚未修復。

### 3. 最小修復約束

修復必須直接對應新錯誤證據，並限於暫時 probe route 的建立或對應刪除方式。不得加入無證據的重試、fallback 指令或全域網絡變更。

若修復改變路由參數或網卡識別方式，必須先以紅燈測試鎖定錯誤行為，再作單一最小改動。現有 journal 必須仍在新增前記錄精確 `/32` route，清理仍須使用相同 tunnel identity 與 route identity；不得在失敗後跳過 route absence 驗證。

如錯誤指向現有設計以外的問題，或最小改動會改變 workflow／清理所有權邊界，停止並重新提交設計，不擴大本次範圍。

### 4. 驗證與清理

每個實作階段均執行相關 Core 測試及 Windows App build。若完成路由修復，再以相同安全流程重測，記錄實際 Healthy／Repaired／Unrepaired／Error，不預設成功。

每次實機測試後必須核對：

- 原 CH、原 GB 及測試副本 SHA-256 不變。
- 原選擇 CH、AutoUpdate On 已還原。
- 沒有執行 Recycle Bin 動作。
- App 正常關閉後，App、`wireguard` 进程及 `WireGuardTunnel$*` 服務為 0。
- 測試前後路由、DNS、網卡無未解釋差異，沒有 WireGuard 殘留。
- 將測試副本移到新的 `live-validation` 目的地，不覆蓋舊證據，原掃描資料夾不再含測試副本。

既有 HTTPS TLS trust error 獨立報告，不當成本次修復造成或修復的項目。真實自動更新不屬於本次驗證。

## 完成定義

- 安全摘要測試證明 `netsh` 錯誤可診斷，且其他原生指令及敏感資料保護沒有倒退。
- 新實機例外提供低層錯誤證據。
- 若證據支持最小修復，該修復有紅綠測試及實機結果；否則明確記錄「已定位，尚未修復」及阻塞原因。
- 所有網絡與設定還原檢查有實際證據。
- 所有產品改動保持未 commit、未 push。
