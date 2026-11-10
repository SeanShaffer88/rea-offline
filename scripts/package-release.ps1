param(
    [Parameter(Mandatory = $true)]
    [string] $Tag,

    [string] $BinaryPath,

    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'

if (($BinaryPath -and -not $OutputDirectory) -or
    ($OutputDirectory -and -not $BinaryPath)) {
    throw 'BinaryPath and OutputDirectory must be provided together.'
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot 'Cargo.toml'
$metadataJson = & cargo metadata --no-deps --format-version 1 --manifest-path $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata failed while reading the package version.'
}

$package = ($metadataJson | ConvertFrom-Json).packages |
    Where-Object { $_.name -eq 'rea-offline' } |
    Select-Object -First 1
if (-not $package) {
    throw "Package rea-offline was not found in $manifestPath."
}

if ($Tag -notmatch '^v(?<version>\d+\.\d+\.\d+)$') {
    throw "Release tag '$Tag' must use the vMAJOR.MINOR.PATCH format."
}
if ($Matches.version -ne $package.version) {
    throw "Release tag '$Tag' does not match Cargo.toml version $($package.version)."
}

if (-not $BinaryPath) {
    return
}

if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Release binary was not found: $BinaryPath"
}

$versionedTag = $Tag
$fileName = "rea-offline-$versionedTag-windows-x86_64.exe"
$destination = Join-Path $OutputDirectory $fileName
$checksumPath = "$destination.sha256"

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
Copy-Item -LiteralPath $BinaryPath -Destination $destination -Force
$hash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $fileName" | Set-Content -LiteralPath $checksumPath -Encoding ascii

Write-Output $destination
Write-Output $checksumPath
