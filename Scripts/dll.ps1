#########################
# Enable DLL SafeSearch #
#########################
Write-Output "Enabling DLL SafeSearch..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1
