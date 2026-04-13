# Task 2 TDD Evidence

## Red Phase
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter IsValidDomain_ReturnsExpectedResult`

Result summary:
- Failed at compile time because `WireguardSplitTunnel.Core.Services.DomainValidator` was missing.
- This was the expected red phase for TDD.

## Green Phase
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter IsValidDomain_ReturnsExpectedResult`

Result summary:
- Passed after implementing `DomainValidator` and the supporting models.
- Test output showed 5 passing cases.

## Reconfirmation Run
Command:
`dotnet test tests/WireguardSplitTunnel.Core.Tests/WireguardSplitTunnel.Core.Tests.csproj --filter IsValidDomain_ReturnsExpectedResult`

Result summary:
- Passed again on a fresh run.
- Output confirmed 5 passing cases.

## Environment Note
- `NU1900` warnings appeared during restore because the sandbox could not reach `https://api.nuget.org/v3/index.json` to fetch vulnerability metadata.
- The warning was non-blocking and did not prevent the targeted test from passing.
