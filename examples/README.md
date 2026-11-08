# Examples

```bat
:: Mode A - inspect an installed program
rea-offline.exe scan "C:\Program Files\SomeApp" --output report.json

:: Mode B - run an untrusted installer contained, diff, analyze, purge
rea-offline.exe sandbox Downloads\setup.msi --output report.json --timeout 600

:: Keep the sandbox for manual follow-up (hive is still unmounted)
rea-offline.exe sandbox setup.exe --keep --output report.json
rea-offline.exe purge %TEMP%\rea_sandbox_<id-from-report>
```

:: Reopen archived evidence without the original target or external REA
rea-offline.exe report report.json --format markdown --output review.md
rea-offline.exe report report.json --fail-on high --quiet
rea-offline.exe gui report.json --from-report

:: A sandbox verdict covers the installer, the install tree and profile drops
rea-offline.exe sandbox setup.exe --fail-on high --output report.json
rea-offline.exe report report.json --format text   :: shows the per-part scores
