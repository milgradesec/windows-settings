# windows-settings

## Configure System

Copy and run this powershell line as administrator.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/milgradesec/windows-settings/master/windows10.ps1'))
```

## Sources

- <https://github.com/Disassembler0/Win10-Initial-Setup-Script>
- <https://www.stigviewer.com>
