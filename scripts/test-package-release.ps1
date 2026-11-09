$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$packageScript = Join-Path $PSScriptRoot 'package-release.ps1'
$manifestPath = Join-Path $repositoryRoot 'Cargo.toml'
$metadataJson = & cargo metadata --no-deps --format-version 1 --manifest-path $manifestPath
if ($LASTEXITCODE -ne 0) {
    throw 'cargo metadata failed while preparing release packaging tests.'
}
$version = (($metadataJson | ConvertFrom-Json).packages |
    Where-Object { $_.name -eq 'rea-offline' } |
    Select-Object -First 1).version
if (-not $version) {
    throw 'Package rea-offline was not found in Cargo.toml.'
}

$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) (
    'rea-offline-release-test-' + [guid]::NewGuid().ToString('N')
)
$binaryPath = Join-Path $temporaryDirectory 'input.exe'
$outputDirectory = Join-Path $temporaryDirectory 'dist'

try {
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    [System.IO.File]::WriteAllBytes($binaryPath, [byte[]](0, 1, 2, 255))

    $differentVersion = if ($version -match '^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$') {
        "v$($Matches.major).$($Matches.minor).$([int]$Matches.patch + 1)"
    } else {
        throw "Unexpected package version format: $version"
    }

    $rejectedMismatch = $false
    try {
        & $packageScript -Tag $differentVersion
    } catch {
        $rejectedMismatch = $_.Exception.Message -like '*does not match Cargo.toml version*'
    }
    if (-not $rejectedMismatch) {
        throw "A tag with a different version was not rejected: $differentVersion"
    }

    $rejectedInvalidFormat = $false
    try {
        & $packageScript -Tag "release-$version"
    } catch {
        $rejectedInvalidFormat = $_.Exception.Message -like '*must use the vMAJOR.MINOR.PATCH format*'
    }
    if (-not $rejectedInvalidFormat) {
        throw 'A release tag outside the vMAJOR.MINOR.PATCH format was not rejected.'
    }

    $tag = "v$version"
    & $packageScript -Tag $tag -BinaryPath $binaryPath -OutputDirectory $outputDirectory
    if ($LASTEXITCODE -ne 0) {
        throw 'Release packaging failed for a matching version tag.'
    }

    $fileName = "rea-offline-$tag-windows-x86_64.exe"
    $packagedBinary = Join-Path $outputDirectory $fileName
    $checksumPath = "$packagedBinary.sha256"
    if (-not (Test-Path -LiteralPath $packagedBinary -PathType Leaf) -or
        -not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw 'Packaging did not produce both the executable and checksum.'
    }

    $expectedHash = (Get-FileHash -LiteralPath $packagedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
    if ($checksumLine -ne "$expectedHash  $fileName") {
        throw 'The generated SHA-256 checksum does not match the packaged executable.'
    }

    Write-Output 'Release packaging tests passed.'
} finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
