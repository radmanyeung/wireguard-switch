# Task 3 TDD Evidence

## Red Phase
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~RouteDiffEngineTests|FullyQualifiedName~StateStoreTests"`

Result summary:
- Failed at compile time because `WireguardSplitTunnel.Core.Services.RouteDiffEngine` and `WireguardSplitTunnel.Core.Services.StateStore` did not exist yet.
- This was the expected red phase for the new Task 3 behavior.

## Green Phase
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter "FullyQualifiedName~RouteDiffEngineTests|FullyQualifiedName~StateStoreTests"`

Result summary:
- Passed after implementing `RouteDiffEngine` and `StateStore`.
- The targeted slice reported 4 passing tests.

## Full Core Tests
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj`

Result summary:
- Passed with 13 tests total.
- Existing `DomainValidator` coverage stayed green.

## Environment Note
- `NU1900` warnings appeared during restore because the sandbox could not reach `https://api.nuget.org/v3/index.json` for vulnerability metadata.
- The warning was non-blocking and did not prevent either the targeted or full test run from passing.
