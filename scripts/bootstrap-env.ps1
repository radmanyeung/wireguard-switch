$ErrorActionPreference = 'Stop'

function Initialize-BootstrapEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $bootstrapRoot = Join-Path $RepoRoot '.build'
    $paths = @{
        Home = Join-Path $bootstrapRoot 'home'
        DotnetCliHome = Join-Path $bootstrapRoot 'dotnet-cli-home'
        NuGetPackages = Join-Path $bootstrapRoot 'nuget\packages'
        Temp = Join-Path $bootstrapRoot 'temp'
        AppData = Join-Path $bootstrapRoot 'appdata'
        LocalAppData = Join-Path $bootstrapRoot 'localappdata'
    }

    foreach ($path in $paths.Values) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }

    $env:HOME = $paths.Home
    $env:USERPROFILE = $paths.Home
    $env:APPDATA = $paths.AppData
    $env:LOCALAPPDATA = $paths.LocalAppData
    $env:DOTNET_CLI_HOME = $paths.DotnetCliHome
    $env:NUGET_PACKAGES = $paths.NuGetPackages
    $env:TEMP = $paths.Temp
    $env:TMP = $paths.Temp
    $env:DOTNET_ADD_GLOBAL_TOOLS_TO_PATH = '0'
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
    $env:DOTNET_NOLOGO = '1'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    $env:MSBUILDDISABLENODEREUSE = '1'
    $env:MSBuildEnableWorkloadResolver = 'false'

    $nugetConfigPath = Join-Path $bootstrapRoot 'temp-nuget.config'
    if (-not (Test-Path $nugetConfigPath)) {
        $xml = @"
<?xml version=""1.0"" encoding=""utf-8""?>
<configuration>
  <packageSources>
    <clear />
    <add key=""nuget.org"" value=""https://api.nuget.org/v3/index.json"" />
  </packageSources>
</configuration>
"@
        Set-Content -Path $nugetConfigPath -Value $xml
    }

    return @{
        BootstrapRoot = $bootstrapRoot
        NuGetConfigPath = $nugetConfigPath
    }
}
