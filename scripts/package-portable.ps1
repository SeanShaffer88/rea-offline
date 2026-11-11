param(
    [Parameter(Mandatory = $true)][string] $BinaryPath,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [string] $CacheDirectory,
    [switch] $CreateZip
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess -or $env:OS -ne 'Windows_NT' -or
    $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Build this bundle on Windows x64.' }
$repository = Split-Path -Parent $PSScriptRoot
$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
if (Test-Path -LiteralPath $OutputDirectory) { throw 'OutputDirectory already exists; choose a new directory.' }
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (-not $CacheDirectory) { $CacheDirectory = Join-Path $repository '.bundle-cache' }
New-Item -ItemType Directory -Force -Path $CacheDirectory | Out-Null
$pinsPath = Join-Path $repository 'portable/dependencies.json'
$pins = Get-Content -Raw -LiteralPath $pinsPath | ConvertFrom-Json
$stage = "$output.staging-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    Copy-Item -LiteralPath $binary -Destination (Join-Path $stage 'rea-offline.exe')
    Copy-Item -LiteralPath (Join-Path $repository 'portable') -Destination (Join-Path $stage 'portable') -Recurse
    Copy-Item -LiteralPath (Join-Path $repository 'README.md'), (Join-Path $repository 'LICENSE') -Destination $stage
    New-Item -ItemType Directory -Path (Join-Path $stage 'licenses') | Out-Null
    foreach ($dependency in $pins.downloads) {
        $cached = Join-Path $CacheDirectory $dependency.file
        if (-not (Test-Path -LiteralPath $cached)) {
            $temporary = "$cached.$([Guid]::NewGuid().ToString('N')).tmp"
            try {
                Write-Host "Downloading $($dependency.name) $($dependency.version)"
                Invoke-WebRequest -Uri $dependency.url -OutFile $temporary
                if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dependency.sha256) {
                    throw "SHA-256 mismatch: $($dependency.name)"
                }
                Move-Item -LiteralPath $temporary -Destination $cached
            } finally {
                if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
            }
        }
        if ((Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash.ToLowerInvariant() -ne $dependency.sha256) {
            throw "Cached download hash mismatch; inspect and remove $cached before retrying."
        }
        $destination = Join-Path $stage $dependency.destination
        if ($dependency.file.EndsWith('.zip')) {
            $expanded = Join-Path $stage ("extract-" + [Guid]::NewGuid().ToString('N'))
            Expand-Archive -LiteralPath $cached -DestinationPath $expanded
            $children = @(Get-ChildItem -LiteralPath $expanded -Force)
            $source = $expanded
            if ($children.Count -eq 1 -and $children[0].PSIsContainer) { $source = $children[0].FullName }
            New-Item -ItemType Directory -Force -Path $destination | Out-Null
            Get-ChildItem -LiteralPath $source -Force | Copy-Item -Destination $destination -Recurse
            Remove-Item -LiteralPath $expanded -Recurse -Force
        } else {
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $cached -Destination $destination
        }
    }
    $node = Join-Path $stage 'tools/node/node.exe'
    $npm = Join-Path $stage 'tools/node/node_modules/npm/bin/npm-cli.js'
    $rea = Join-Path $stage 'tools/rea'
    New-Item -ItemType Directory -Path $rea | Out-Null
    '{"name":"rea-portable-runtime","version":"1.0.0","private":true}' |
        Set-Content -LiteralPath (Join-Path $rea 'package.json') -Encoding ascii
    # Keep platform-matched optional prebuilds (e.g. node-pty); never run
    # dependency lifecycle scripts or fetch native provider installers.
    & $node $npm install --prefix $rea --ignore-scripts --omit=dev --no-audit --no-fund --registry=https://registry.npmjs.org "rea-agents@$($pins.rea_version)"
    if ($LASTEXITCODE -ne 0) { throw 'Pinned upstream REA dependency installation failed.' }
    # npm locks legitimately have packages[""]; PSCustomObject JSON parsing
    # rejects that empty property. Parse with the bundled Node runtime.
    $integrity = & $node -e "const fs=require('node:fs');process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1],'utf8')).packages['node_modules/rea-agents'].integrity)" (Join-Path $rea 'package-lock.json')
    if ($LASTEXITCODE -ne 0 -or $integrity -ne $pins.rea_integrity) {
        throw 'Installed REA package integrity did not match the pinned npm tarball.'
    }
    @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0portable\rea.ps1" %*
exit /b %errorlevel%
'@ | Set-Content -LiteralPath (Join-Path $stage 'rea.cmd') -Encoding ascii
    @'
@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0portable\Export-Forensics.ps1" %*
exit /b %errorlevel%
'@ | Set-Content -LiteralPath (Join-Path $stage 'Analyze-Program.cmd') -Encoding ascii
    $notices = @('# Bundled components', '', 'Preserve all included licenses/legal notices when redistributing.', '')
    foreach ($d in $pins.downloads) { $notices += "- $($d.name) $($d.version): $($d.license). Source: $($d.url)" }
    $notices += '- REA: MIT. Exact npm version/integrity and transitive dependencies are recorded in portable/dependencies.json and tools/rea/package-lock.json. All installed package license files are retained.'
    $notices += '- Temurin corresponding source is included under licenses/, alongside the complete distributed JDK legal notices.'
    $notices += '- No commercial decompiler licenses, activation keys, target-specific runtimes, Frida native runtime or browser automation downloads are bundled/verified.'
    # Rust/llama/Node/native Ghidra helpers may need the MSVC CRT. Ship
    # app-local redistributables from the licensed Windows build toolchain,
    # rather than assume Visual Studio is installed on the analyst's PC.
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Build Tools redistributable CRT payload is required to build the portable bundle.' }
    $visualStudio = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $versions = @(Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC/Redist/MSVC') -Directory | Sort-Object Name -Descending)
    $crt = $null
    foreach ($version in $versions) {
        $matches = @(Get-ChildItem -LiteralPath (Join-Path $version.FullName 'x64') -Directory -Filter 'Microsoft.VC*.CRT' -ErrorAction SilentlyContinue)
        if ($matches.Count -gt 0) { $crt = $matches[0].FullName; break }
    }
    if (-not $crt) { throw 'Could not find the x64 app-local MSVC CRT redistributables.' }
    $runtime = Join-Path $stage 'tools/vc-runtime'
    New-Item -ItemType Directory -Path $runtime | Out-Null
    foreach ($dll in Get-ChildItem -LiteralPath $crt -File -Filter '*.dll') {
        Copy-Item -LiteralPath $dll.FullName -Destination $runtime
        foreach ($directory in @($stage, (Join-Path $stage 'tools/llama'), (Join-Path $stage 'tools/node'))) {
            if (-not (Test-Path -LiteralPath (Join-Path $directory $dll.Name))) {
                Copy-Item -LiteralPath $dll.FullName -Destination $directory
            }
        }
    }
    $notices += '- Microsoft Visual C++ x64 app-local runtime: copied from the licensed build toolchain redistributable CRT directory; Microsoft redistribution terms apply. Runtime bytes are recorded in bundle-manifest.json.'
    $crtLicense = Get-ChildItem -LiteralPath (Split-Path -Parent (Split-Path -Parent $crt)) -File |
        Where-Object { $_.Name -match 'license|eula' }
    foreach ($license in $crtLicense) { Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $stage 'licenses') }
    $notices | Set-Content -LiteralPath (Join-Path $stage 'THIRD_PARTY_NOTICES.md') -Encoding utf8
    # Hash every file, including weights, DLLs, dependency lock and licenses.
    $records = @(Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
        @{ path = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
           bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    @{ schema_version = 1; platform = 'windows-x86_64'; files = $records } |
        ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $stage 'bundle-manifest.json') -Encoding utf8
    Move-Item -LiteralPath $stage -Destination $output
    if ($CreateZip) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($output, "$output.zip")
        $hash = (Get-FileHash -LiteralPath "$output.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $([IO.Path]::GetFileName($output)).zip" | Set-Content -LiteralPath "$output.zip.sha256" -Encoding ascii
    }
    Write-Output $output
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
