# Test Config 例外診斷設計

## 目的

實機 `Test Config` 目前只記錄 `Config check. status=Fatal ... reason=WorkflowFailed`，UI 只顯示一般失敗訊息，無法判斷原生測試、清理或還原階段的實際例外。今次先保留完整例外，再以相同測試副本重現，取得根因證據。

## 範圍

- 修改 `MainWindow.ConfigCheck.cs` 的 `WorkflowFailed` 例外處理，透過現有 `IAppLogger.Error(string, Exception?)` 寫入例外詳情。
- 在現有 `ConfigCheckUiContractTests` 加一項合約測試，要求 `WorkflowFailed` catch 將實際例外傳給 `logger.Error`。
- Build Windows App、跑相關測試，再以隔離的 `GB-tested.conf` 副本進行一次實機重現。
- 取得根因後，先報告證據，再決定最小修復；今次診斷改動本身不假設能修復連線。

## 不變事項及安全邊界

- 不記錄 `.conf` 內容、PrivateKey、完整原生指令參數或任何私密金鑰。
- 保留現有使用者訊息、回收筒預設 No、原設定還原及正常關閉保護。
- 實機測試前暫停自動更新，完成後還原 On；不執行真實更新。
- 回收筒提示一律選 No；清理失敗選 Cancel，不強行關閉。
- 不 commit、pull 或 push；設計文件亦只寫入工作區。
- 測試副本只含先前移除 `PersistentKeepalive` 的隔離版本，原 `CH.conf` 及 `GB.conf` 不得改動。

## 資料流

1. `ConfigCheckWorkflow.RunAsync` 拋出例外，可能包含 `AggregateException` 的主錯誤及還原錯誤。
2. `RunWorkflowAsync` 的現有 catch 以 `logger.Error("Config check workflow failed.", ex)` 記錄例外類型、訊息、stack trace 及內層例外。
3. 現有 `LogConfigCheck("Fatal", ..., "WorkflowFailed")` 和一般 UI 訊息保持不變。
4. 實機重現後，只讀取 runtime log 的相關區段及非敏感交易 journal，不輸出備份或設定內容。

## 驗證

- 新合約測試在實作前失敗，加入例外紀錄後通過。
- `ConfigCheckUiContractTests` 全過，Windows App build 無錯誤。
- 實機測試必須核對實際結果、原 CH／GB hash、選擇、自動更新、測試副本、隧道服務及正常關閉。
- 若測試仍失敗，runtime log 必須提供可用於定位的實際例外；若沒有，繼續調查紀錄路徑，不猜測根因。
