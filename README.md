# 🔒 Windows Settings

🚧 Under construction...

## Introduction

This project is divided into two main files.

`windows10.ps1`, a powershell script to configure many Windows 10/11 system settings and some third-party software for increased privacy and security.

`ExploitGuard/ExploitSettings.xml`, contains settings with aditional exploit mitigations for many system services and third-party software.

### Software Covered

This list includes applications with configuration changed by the main script:

* Microsoft Office
* Microsoft Edge
* Google Chrome
* Brave Browser
* Mozilla Firefox
* Zoom

## How to configure your system

To configure your system copy and run this powershell line as administrator (Creates a scheduled task to run daily):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/milgradesec/windows-settings/main/windows10.ps1'))
```

## Sources

* <https://github.com/Disassembler0/Win10-Initial-Setup-Script>
* <https://www.stigviewer.com>
* <https://admx.help/>
* <https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat>
* <https://gist.github.com/alirobe/7f3b34ad89a159e6daa1>
* <https://gist.github.com/chuckwagoncomputing/24f968083292361d7a8bafba0bbf371d>

## License

GNU General Public License v3.0
