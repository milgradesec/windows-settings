##########################
# Disable WinHelp Macros #
##########################
Write-Output "Disabling WinHelp Macros..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Winhelp" -Name "AllowProgrammaticMacrosInWinhelp" -Value 0
