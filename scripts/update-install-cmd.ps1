param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$marker = '# WGST_EMBEDDED_INSTALLER_V0210'
$sourcePath = Join-Path $PSScriptRoot 'install-bootstrap.ps1'
$commandPath = Join-Path $RepositoryRoot 'install.cmd'
$source = [IO.File]::ReadAllText($sourcePath)
$command = [IO.File]::ReadAllText($commandPath)
$index = $command.LastIndexOf($marker, [StringComparison]::Ordinal)
if ($index -lt 0) {
    throw 'install.cmd embedded bootstrap marker is missing.'
}
$embedded = $command.Substring($index + $marker.Length).TrimStart("`r", "`n")
$getTokenSignature = {
    param([string]$Text)
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput(
        $Text,
        [ref]$tokens,
        [ref]$errors)
    if ($errors.Count -gt 0) {
        throw "Installer bootstrap parse failed: $($errors[0].Message)"
    }
    return [string]::Join("`n", @($tokens | Where-Object {
        $_.Kind -notin @('NewLine', 'LineContinuation', 'Comment', 'EndOfInput')
    } | ForEach-Object { "$($_.Kind):$($_.Text)" }))
}
if ((& $getTokenSignature $embedded) -cne
    (& $getTokenSignature $source)) {
    if ($Check) {
        throw 'install.cmd embedded bootstrap is out of sync with scripts/install-bootstrap.ps1.'
    }
    $prefix = $command.Substring(0, $index + $marker.Length).TrimEnd("`r", "`n")
    $updated = $prefix + "`r`n" + $source.TrimStart("`r", "`n")
    [IO.File]::WriteAllText(
        $commandPath,
        $updated.Replace("`n", "`r`n"),
        [Text.UTF8Encoding]::new($false))
}

[void](& $getTokenSignature $source)
Write-Output 'install.cmd embedded bootstrap is synchronized.'
