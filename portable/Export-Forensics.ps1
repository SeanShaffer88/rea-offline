param(
    [Parameter(Mandatory = $true)][string] $Target,
    [Parameter(Mandatory = $true)][string] $Output,
    [switch] $IncludeFiles,
    [switch] $RunInstaller,
    [string[]] $InstallerArguments = @(),
    [switch] $Deep,
    [switch] $SkipModel,
    [switch] $Zip,
    [ValidateRange(1,10000)][int] $MaxFiles = 20,
    [ValidateRange(1,100000)][int] $MaxFunctions = 2000,
    [ValidateRange(30,7200)][int] $DeepTimeoutSeconds = 900
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$targetPath = (Resolve-Path -LiteralPath $Target).Path
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'Choose a new output folder; existing evidence is never overwritten.' }
$env:JAVA_HOME = Join-Path $root 'tools/jdk'
$env:JAVA_HOME_OVERRIDE = $env:JAVA_HOME
$env:GHIDRA_INSTALL_DIR = Join-Path $root 'tools/ghidra'
$env:REA_ANALYSIS_PROVIDER = 'ghidra'
$env:PATH = (Join-Path $root 'tools/vc-runtime') + ';' + (Join-Path $root 'tools/node') + ';' + (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:PATH
function Write-Utf8([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}
$exportArgs = @('forensic', $targetPath, '--output', $outputPath)
if ($IncludeFiles) { $exportArgs += '--include-files' }
if ($RunInstaller) { $exportArgs += '--run-installer' }
if ($InstallerArguments.Count -gt 0) {
    if (-not $RunInstaller) { throw 'InstallerArguments requires RunInstaller.' }
    $exportArgs += '--'; $exportArgs += $InstallerArguments
}
Write-Host 'Exporting local file/folder evidence. Treat installers as untrusted; Job Objects are not secure malware isolation.'
& (Join-Path $root 'rea-offline.exe') @exportArgs
if ($LASTEXITCODE -ne 0) { throw 'Native forensic export failed.' }
$statuses = New-Object Collections.Generic.List[object]
$report = Get-Content -Raw -LiteralPath (Join-Path $outputPath 'report.json') | ConvertFrom-Json
$isFolder = (Get-Item -LiteralPath $targetPath).PSIsContainer
$node = Join-Path $root 'tools/node/node.exe'
$rea = Join-Path $root 'tools/rea/node_modules/rea-agents/scripts/rea.mjs'
New-Item -ItemType Directory -Path (Join-Path $outputPath 'upstream') | Out-Null
try {
    # Explicit version-pinned upstream REA; no npx/npm or implicit installs.
    $upstreamTarget = $targetPath
    # Upstream directory analysis is aimed at JS/Electron applications.
    # For native installed folders, inspect an executable, not the directory.
    if ($isFolder -and -not (Test-Path -LiteralPath (Join-Path $targetPath 'package.json')) -and
        -not (Test-Path -LiteralPath (Join-Path $targetPath 'resources/app.asar'))) {
        $native = @($report.report.files | Where-Object { $_.format -eq 'PE' } | Select-Object -First 1)
        if ($native.Count -gt 0) { $upstreamTarget = Join-Path $targetPath $native[0].path }
    }
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & $node $rea analyze $upstreamTarget --json 2> (Join-Path $outputPath 'upstream/rea.stderr.txt')
        $exit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    Write-Utf8 (Join-Path $outputPath 'upstream/rea-analysis.json') ($raw -join "`n")
    $statuses.Add(@{tool='rea';exit_code=$exit;success=($exit -eq 0);scope='upstream overview; inspect its coverage limitations'})
} catch {
    $statuses.Add(@{tool='rea';success=$false;error=$_.Exception.Message})
}
if ($Deep) {
    New-Item -ItemType Directory -Path (Join-Path $outputPath 'deep') | Out-Null
    $candidates = @($report.report.files | Where-Object { $_.format -eq 'PE' })
    foreach ($candidate in $candidates) {
        $source = $targetPath
        if ($isFolder) { $source = Join-Path $targetPath $candidate.path }
        $candidate | Add-Member -NotePropertyName evidence_source -NotePropertyValue $source
    }
    $installedReport = Join-Path $outputPath 'installed-report.json'
    if (Test-Path -LiteralPath $installedReport) {
        $installed = Get-Content -Raw -LiteralPath $installedReport | ConvertFrom-Json
        $added = @($installed.files | Where-Object { $_.format -eq 'PE' })
        foreach ($candidate in $added) {
            $candidate | Add-Member -NotePropertyName evidence_source -NotePropertyValue (Join-Path $outputPath ('installed-files/' + $candidate.path))
        }
        $candidates += $added
    }
    $selected = @($candidates | Select-Object -First $MaxFiles)
    $statuses.Add(@{tool='ghidra-scope';candidates=$candidates.Count;selected=$selected.Count;
        omitted=($candidates.Count - $selected.Count);max_functions_per_file=$MaxFunctions})
    $headless = Join-Path $root 'tools/ghidra/support/analyzeHeadless.bat'
    $index = 0
    foreach ($entry in $selected) {
        $source = $entry.evidence_source
        $name = '{0:D5}-{1}' -f $index, $entry.sha256.Substring(0,16)
        $index++
        $destination = Join-Path $outputPath "deep/$name.jsonl"
        $project = Join-Path ([IO.Path]::GetTempPath()) ("rea-ghidra-" + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $project | Out-Null
        try {
            # Metadata-only managed detection does not load target code.
            $managed = $false
            try { $null = [Reflection.AssemblyName]::GetAssemblyName($source); $managed = $true } catch { }
            if ($managed) {
                foreach ($operation in @('inspect-managed-artifact','inspect-managed-members')) {
                    $previousPreference = $ErrorActionPreference
                    $ErrorActionPreference = 'Continue'
                    try {
                        $managedOutput = & $node $rea $operation $source --json 2> (Join-Path $outputPath "deep/$name-$operation.stderr.txt")
                        $managedExit = $LASTEXITCODE
                    } finally { $ErrorActionPreference = $previousPreference }
                    Write-Utf8 (Join-Path $outputPath "deep/$name-$operation.json") ($managedOutput -join "`n")
                    $statuses.Add(@{tool=$operation;source=$entry.path;exit_code=$managedExit;success=($managedExit -eq 0)})
                }
            }
            $arguments = @($project,'evidence','-import',$source,'-analysisTimeoutPerFile','600',
                '-scriptPath',(Join-Path $PSScriptRoot 'ghidra'),'-postScript','ExportForensic.java',
                $destination,"$MaxFunctions",'-deleteProject')
            # Ghidra's trusted launcher is a .bat file. Refuse cmd-expansion
            # characters in paths rather than concatenate executable syntax.
            foreach ($part in @($headless) + $arguments) {
                if ($part -match '[&|<>^%!`"\r\n]') { throw 'Deep-analysis paths contain unsupported cmd expansion characters; move to a simple local path.' }
            }
            $quoted = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
            $commandLine = '/d /s /c ""' + $headless + '" ' + $quoted + '"'
            $process = Start-Process -FilePath $env:ComSpec -ArgumentList $commandLine -PassThru -NoNewWindow `
                -RedirectStandardOutput (Join-Path $outputPath "deep/$name.stdout.txt") `
                -RedirectStandardError (Join-Path $outputPath "deep/$name.stderr.txt")
            $timedOut = -not $process.WaitForExit($DeepTimeoutSeconds * 1000)
            if ($timedOut) {
                & taskkill.exe /PID $process.Id /T /F | Out-Null
                $process.WaitForExit()
            }
            $process.Refresh()
            $exit = $process.ExitCode
            $process.Dispose()
            $header = $null; $footer = $null
            if (Test-Path -LiteralPath $destination) {
                $header = Get-Content -LiteralPath $destination -TotalCount 1 | ConvertFrom-Json
                $footer = Get-Content -LiteralPath $destination -Tail 1 | ConvertFrom-Json
            }
            $identityMatches = ($null -ne $header -and $header.source_sha256 -eq $entry.sha256)
            $finished = ($null -ne $footer -and $footer.kind -eq 'completion')
            $statuses.Add(@{tool='ghidra';source=$entry.path;source_sha256=$entry.sha256;output="deep/$name.jsonl";
                exit_code=$exit;timed_out=$timedOut;identity_matches=$identityMatches;footer_present=$finished;
                success=($exit -eq 0 -and -not $timedOut -and $identityMatches -and $finished);
                completion=$footer})
        } catch {
            $statuses.Add(@{tool='ghidra';source=$entry.path;success=$false;error=$_.Exception.Message})
        } finally {
            if (Test-Path -LiteralPath $project) { Remove-Item -LiteralPath $project -Recurse -Force -ErrorAction Continue }
        }
    }
}
if (-not $SkipModel) {
    try {
        & (Join-Path $root 'rea.cmd') ask 'Explain the observed program architecture, suspicious capabilities, and evidence gaps. Do not claim full behavioral replication.' `
            --target $targetPath --output (Join-Path $outputPath 'assistant.json')
        $statuses.Add(@{tool='micro-llm';success=($LASTEXITCODE -eq 0);scope='advisory native evidence summary, not the complete deep export'})
    } catch { $statuses.Add(@{tool='micro-llm';success=$false;error=$_.Exception.Message}) }
}
Write-Utf8 (Join-Path $outputPath 'analysis-status.json') (
    @{schema_version=1;tools=@($statuses.ToArray());deep_requested=[bool]$Deep;replication_complete=$false;
      note='Tool completion is not behavioral coverage. Read per-function failures, caps, export issues and reconstruction unknowns.'} |
    ConvertTo-Json -Depth 30)
# Recompute after adding tool outputs so every exported file has provenance.
$records = @(Get-ChildItem -LiteralPath $outputPath -Recurse -File |
    Where-Object { $_.FullName -ne (Join-Path $outputPath 'manifest.json') } |
    Sort-Object FullName | ForEach-Object {
        @{path=$_.FullName.Substring($outputPath.Length+1).Replace('\','/');bytes=$_.Length;
          sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
Write-Utf8 (Join-Path $outputPath 'manifest.json') (
    @{manifest_version=1;hash_algorithm='sha256';files=$records;note='Manifest excludes itself; hashes do not establish behavioral completeness.'} |
    ConvertTo-Json -Depth 12)
if ($Zip) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($outputPath, "$outputPath.zip")
}
Write-Host "Evidence exported to $outputPath. Review analysis-status.json and reconstruction.json before using it."
$failures = @($statuses.ToArray() | Where-Object { $_.ContainsKey('success') -and -not $_.success })
if ($failures.Count -gt 0) { Write-Warning "$($failures.Count) tool stage(s) failed; partial evidence was preserved."; exit 3 }
exit 0
