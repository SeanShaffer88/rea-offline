# Launch without changing the user's global PATH, registry or firewall.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$root = Split-Path -Parent $PSScriptRoot
$env:JAVA_HOME = Join-Path $root 'tools/jdk'
$env:GHIDRA_INSTALL_DIR = Join-Path $root 'tools/ghidra'
$env:REA_ANALYSIS_PROVIDER = 'ghidra'
$env:REA_PATH = Join-Path $root 'tools/rea/node_modules/rea-agents/scripts/rea.mjs'
$env:PATH = (Join-Path $root 'tools/vc-runtime') + ';' + (Join-Path $root 'tools/node') + ';' + (Join-Path $env:JAVA_HOME 'bin') + ';' + $env:PATH
$clientArgs = @($args)
if ($clientArgs.Count -gt 0 -and $clientArgs[0] -eq 'ask') {
    if (-not ($clientArgs -match '^--model(=|$)')) {
        $clientArgs += @('--model', (Join-Path $root 'models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf'))
    }
    if (-not ($clientArgs -match '^--llm(=|$)')) {
        $clientArgs += @('--llm', (Join-Path $root 'tools/llama/llama-completion.exe'))
    }
}
& (Join-Path $root 'rea-offline.exe') @clientArgs
exit $LASTEXITCODE
