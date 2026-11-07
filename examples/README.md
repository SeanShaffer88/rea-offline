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
